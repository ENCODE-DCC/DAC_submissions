#!/usr/bin/env python
'''Take a CSV with file metadata, POST new file objects to the ENCODE DCC, upload files to the ENCODE cloud bucket'''

import os, sys, logging, urlparse, requests, csv, StringIO, re, copy, json, subprocess, hashlib

logger = logging.getLogger(__name__)

EPILOG = '''Notes:

Examples:

	%(prog)s
'''

CSV_ARGS = {
		'delimiter': ',',
		'quotechar': '"',
		'quoting': csv.QUOTE_MINIMAL,
		'dialect': 'excel'
}

GET_HEADERS = {'accept': 'application/json'}
POST_HEADERS = {'accept': 'application/json', 'content-type': 'application/json'}

def get_args():
	import argparse
	parser = argparse.ArgumentParser(
		description=__doc__, epilog=EPILOG,
		formatter_class=argparse.RawDescriptionHelpFormatter)

	parser.add_argument('infile',		help='CSV file metadata to POST', nargs='?', type=argparse.FileType('rU'), default=sys.stdin)
	parser.add_argument('--outfile',	help='CSV output report', type=argparse.FileType(mode='wb',bufsize=0), default=sys.stdout)
	parser.add_argument('--debug',		help="Print debug messages", default=False, action='store_true')
	parser.add_argument('--server',		help="The server to POST to.", default=os.getenv('ENCODE_SERVER',None))
	parser.add_argument('--authid',		help="The authorization key ID for the server.", default=os.getenv('ENCODE_AUTHID',None))
	parser.add_argument('--authpw',		help="The authorization key for the server.", default=os.getenv('ENCODE_AUTHPW',None))
	parser.add_argument('--dryrun',		help="Don't POST to the database, just validate input.", default=False, action='store_true')
	parser.add_argument('--encvaldata',	help="Directory in which https://github.com/ENCODE-DCC/encValData.git is cloned.", default=os.path.expanduser("~/encValData/"))

	args = parser.parse_args()

	if args.debug:
		logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
	else: #use the defaulf logging level
		logging.basicConfig(format='%(levelname)s:%(message)s')

	if args.debug:
		logger.setLevel(logging.DEBUG)
	else:
		logger.setLevel(logging.INFO)

	if not args.server:
		logger.error('Server name must be specified on the command line or in environment ENCODE_SERVER')
		sys.exit(1)
	if not args.authid or not args.authpw:
		logger.error('Authorization keypair must be specified on the command line or in environment ENCODE_AUTHID, ENCODE_AUTHPW')
		sys.exit(1)
	if not os.path.isdir(args.encvaldata):
		logger.error('No ENCODE validation data.  git clone https://github.com/ENCODE-DCC/encValData.git')
		sys.exit(1)

	return args

def md5(path):
	md5sum = hashlib.md5()
	with open(path, 'rb') as f:
		for chunk in iter(lambda: f.read(1024*1024), b''):
			md5sum.update(chunk)
	return md5sum.hexdigest()

	# This does not depend on hashlib
	# if 'md5_command' not in globals():
	# 	global md5_command
	# 	if subprocess.check_output('which md5', shell=True):
	# 		md5_command = 'md5 -q'
	# 	elif subprocess.check_output('which md5sum', shell=True):
	# 		md5_command = 'md5sum'
	# 	else:
	# 		md5_command = ''
	# if not md5_command:
	# 	logger.error("No MD5 command found (tried md5 and md5sum)")
	# 	return None
	# else:
	# 	try:
	# 		md5_output = subprocess.check_output(' '.join([md5_command, fn]), shell=True)
	# 	except:
	# 		return None
	# 	else:
	# 		return md5_output.partition(' ')[0].rstrip()

def test_encode_keys(server,keypair):
	test_URI = "ENCBS000AAA"
	url = urlparse.urljoin(server,test_URI)
	r = requests.get(url, auth=keypair, headers=GET_HEADERS)
	try:
		r.raise_for_status()
	except:
		logger.debug('test_encode_keys got response %s' %(r.text))
		return False
	else:
		return True

def input_csv(fh):
	csv_args = CSV_ARGS
	input_fieldnames = csv.reader(fh, **csv_args).next()
	return csv.DictReader(fh, fieldnames=input_fieldnames, **csv_args)

def output_csv(fh,fieldnames):
	csv_args = CSV_ARGS
	additional_fields = ['accession','aws_return']
	output_fieldnames = [fn for fn in fieldnames if fn] + additional_fields
	output = csv.DictWriter(fh, fieldnames=output_fieldnames, **csv_args)
	return output

def init_csvs(in_fh,out_fh):
	input_reader = input_csv(in_fh)
	output_writer = output_csv(out_fh,input_reader.fieldnames)
	return input_reader, output_writer

def validate_file(f_obj, encValData, assembly=None):
	path = f_obj.get('submitted_file_name')
	file_format = f_obj.get('file_format')
	file_format_type = f_obj.get('file_format_type')
	output_type = f_obj.get('output_type')

	gzip_types = [
		"CEL",
		"bam",
		"bed",
		"csfasta",
		"csqual",
		"fasta",
		"fastq",
		"gff",
		"gtf",
		"tar",
		"sam",
		"wig"
	]

	magic_number = open(path, 'rb').read(2)
	is_gzipped = magic_number == b'\x1f\x8b'
	if file_format in gzip_types:
		if not is_gzipped:
			logger.warning('%s: Expect %s format to be gzipped' %(path,file_format))
	else:
		if is_gzipped:
			logger.warning('%s: Expect %s format to be un-gzipped' %(path,file_format))

	if assembly:
		chromInfo = '-chromInfo=%s/%s/chrom.sizes' % (encValData, assembly)
	else:
		chromInfo = None

	validate_map = {
		('fasta', None): ['-type=fasta'],
		('fastq', None): ['-type=fastq'],
		('bam', None): ['-type=bam', chromInfo],
		('bigWig', None): ['-type=bigWig', chromInfo],
		('bed', 'bed3'): ['-type=bed3', chromInfo],
		('bigBed', 'bed3'): ['-type=bed3', chromInfo],
		('bed', 'bed6'): ['-type=bed6+', chromInfo],
		('bigBed', 'bed6'): ['-type=bigBed6+', chromInfo],
		('bed', 'bedLogR'): ['-type=bed9+1', chromInfo, '-as=%s/as/bedLogR.as' % encValData],
		('bigBed', 'bedLogR'): ['-type=bigBed9+1', chromInfo, '-as=%s/as/bedLogR.as' % encValData],
		('bed', 'bedMethyl'): ['-type=bed9+2', chromInfo, '-as=%s/as/bedMethyl.as' % encValData],
		('bigBed', 'bedMethyl'): ['-type=bigBed9+2', chromInfo, '-as=%s/as/bedMethyl.as' % encValData],
		('bed', 'broadPeak'): ['-type=bed6+3', chromInfo, '-as=%s/as/broadPeak.as' % encValData],
		('bigBed', 'broadPeak'): ['-type=bigBed6+3', chromInfo, '-as=%s/as/broadPeak.as' % encValData],
		('bed', 'gappedPeak'): ['-type=bed12+3', chromInfo, '-as=%s/as/gappedPeak.as' % encValData],
		('bigBed', 'gappedPeak'): ['-type=bigBed12+3', chromInfo, '-as=%s/as/gappedPeak.as' % encValData],
		('bed', 'narrowPeak'): ['-type=bed6+4', chromInfo, '-as=%s/as/narrowPeak.as' % encValData],
		('bigBed', 'narrowPeak'): ['-type=bigBed6+4', chromInfo, '-as=%s/as/narrowPeak.as' % encValData],
		('bed', 'bedRnaElements'): ['-type=bed6+3', chromInfo, '-as=%s/as/bedRnaElements.as' % encValData],
		('bigBed', 'bedRnaElements'): ['-type=bed6+3', chromInfo, '-as=%s/as/bedRnaElements.as' % encValData],
		('bed', 'bedExonScore'): ['-type=bed6+3', chromInfo, '-as=%s/as/bedExonScore.as' % encValData],
		('bigBed', 'bedExonScore'): ['-type=bigBed6+3', chromInfo, '-as=%s/as/bedExonScore.as' % encValData],
		('bed', 'bedRrbs'): ['-type=bed9+2', chromInfo, '-as=%s/as/bedRrbs.as' % encValData],
		('bigBed', 'bedRrbs'): ['-type=bigBed9+2', chromInfo, '-as=%s/as/bedRrbs.as' % encValData],
		('bed', 'enhancerAssay'): ['-type=bed9+1', chromInfo, '-as=%s/as/enhancerAssay.as' % encValData],
		('bigBed', 'enhancerAssay'): ['-type=bigBed9+1', chromInfo, '-as=%s/as/enhancerAssay.as' % encValData],
		('bed', 'modPepMap'): ['-type=bed9+7', chromInfo, '-as=%s/as/modPepMap.as' % encValData],
		('bigBed', 'modPepMap'): ['-type=bigBed9+7', chromInfo, '-as=%s/as/modPepMap.as' % encValData],
		('bed', 'pepMap'): ['-type=bed9+7', chromInfo, '-as=%s/as/pepMap.as' % encValData],
		('bigBed', 'pepMap'): ['-type=bigBed9+7', chromInfo, '-as=%s/as/pepMap.as' % encValData],
		('bed', 'openChromCombinedPeaks'): ['-type=bed9+12', chromInfo, '-as=%s/as/openChromCombinedPeaks.as' % encValData],
		('bigBed', 'openChromCombinedPeaks'): ['-type=bigBed9+12', chromInfo, '-as=%s/as/openChromCombinedPeaks.as' % encValData],
		('bed', 'peptideMapping'): ['-type=bed6+4', chromInfo, '-as=%s/as/peptideMapping.as' % encValData],
		('bigBed', 'peptideMapping'): ['-type=bigBed6+4', chromInfo, '-as=%s/as/peptideMapping.as' % encValData],
		('bed', 'shortFrags'): ['-type=bed6+21', chromInfo, '-as=%s/as/shortFrags.as' % encValData],
		('bigBed', 'shortFrags'): ['-type=bigBed6+21', chromInfo, '-as=%s/as/shortFrags.as' % encValData],
		('rcc', None): ['-type=rcc'],
		('idat', None): ['-type=idat'],
		('bedpe', None): ['-type=bed3+', chromInfo],
		('bedpe', 'mango'): ['-type=bed3+', chromInfo],
		('gtf', None): None,
		('tar', None): None,
		('tsv', None): None,
		('csv', None): None,
		('2bit', None): None,
		('csfasta', None): ['-type=csfasta'],
		('csqual', None): ['-type=csqual'],
		('CEL', None): None,
		('sam', None): None,
		('wig', None): None,
		('hdf5', None): None,
		('gff', None): None
	}

	#special cases
	if (file_format, file_format_type) == ('bed', 'bed3') and output_type in ['predicted forebrain enhancers', 'predicted heart enhancers', 'predicted enhancers']:
		validate_args = ['-type=bed3+', chromInfo, '-as=%s/as/enhancer_prediction.as' %(encValData)]
	else:
		validate_args = validate_map.get((file_format, file_format_type))

	if validate_args is None:
		logger.warning('No rules to validate file_format %s and file_format_type %s' %(file_format, file_format_type))
		return False
	else:
		try:
			subprocess.check_output(['validateFiles'] + validate_args + [path])
		except subprocess.CalledProcessError as e:
			logger.error(e.output)
			return False
		else:
			logger.debug("%s: validateFiles passed" %(path))
			return True

def post_file(file_metadata, server, keypair, dryrun=False):
	local_path = file_metadata.get('submitted_file_name')
	if not file_metadata.get('md5sum'):
		file_metadata['md5sum'] = md5(local_path)
	try:
		logger.debug("POST JSON: %s" %(json.dumps(file_metadata)))
	except:
		pass
	if dryrun:
		file_obj = copy.copy(file_metadata)
		file_obj.update({'accession':None})
		return file_obj
	else:
		url = urlparse.urljoin(server,'/files/')
		r = requests.post(url, auth=keypair, headers=POST_HEADERS, data=json.dumps(file_metadata))
		try:
			r.raise_for_status()
		except:
			logger.warning('POST failed: %s %s' %(r.status_code, r.reason))
			logger.warning(r.text)
			return None
		else:
			return r.json()['@graph'][0]

def upload_file(file_obj, dryrun=False):
	if dryrun:
		return None
	else:
		creds = file_obj['upload_credentials']
		logger.debug('AWS creds: %s' %(creds))
		env = os.environ.copy()
		env.update({
			'AWS_ACCESS_KEY_ID': creds['access_key'],
			'AWS_SECRET_ACCESS_KEY': creds['secret_key'],
			'AWS_SECURITY_TOKEN': creds['session_token'],
		})
		path = file_obj.get('submitted_file_name')
		try:
			subprocess.check_call(['aws', 's3', 'cp', path, creds['upload_url']], env=env)
		except subprocess.CalledProcessError as e:
			# The aws command returns a non-zero exit code on error.
			logger.error("AWS upload failed with exit code %d" %(e.returncode))
			return e.returncode
		else:
			return 0

def process_row(row):
	json_payload = {}
	for key,value in row.iteritems():
		if not key:
			continue
		try:
			json_payload.update({key:json.loads(value)})
		except:
			try:
				json_payload.update({key:json.loads('"%s"' %(value))})
			except:
				logger.warning('Could not convert field %s value %s to JSON' %(n,key,value))
				return None
	return json_payload

def main():

	args = get_args()

	server = args.server
	keypair = (args.authid, args.authpw)

	if not test_encode_keys(server, keypair):
		logger.error("Invalid ENCODE server or keys: server=%s authid=%s authpw=%s" %(args.server,args.authid,args.authpw))
		sys.exit(1)

	try:
		subprocess.check_output('which validateFiles', shell=True)
	except:
		logger.error("validateFiles is not in path. See http://hgdownload.cse.ucsc.edu/admin/exe/")
		sys.exit(1)

	input_csv, output_csv = init_csvs(args.infile, args.outfile)

	output_csv.writeheader()

	for n,row in enumerate(input_csv,start=2): #row 1 is the header

		if not validate_file(row, args.encvaldata, row.get('assembly')):
			logger.warning('Skipping row %d: file %s failed validation' %(n,row['submitted_file_name']))
			continue

		json_payload = process_row(row)
		if not json_payload:
			logger.warning('Skipping row %d: invalid field format for JSON' %(n))
			continue

		file_object = post_file(json_payload, server, keypair, args.dryrun)
		if not file_object:
			logger.warning('Skipping row %d: POST file object failed' %(n))
			continue

		aws_return_code = upload_file(file_object, args.dryrun)
		if aws_return_code:
			logger.warning('Row %d: Non-zero AWS upload return code %d' %(aws_return_code))

		output_row = {}
		for key in output_csv.fieldnames:
			output_row.update({key:file_object.get(key)})
		output_row.update({'aws_return':aws_return_code})

		output_csv.writerow(output_row)


if __name__ == '__main__':
	main()
