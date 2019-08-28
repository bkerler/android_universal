#import lz4.frame
import sys
import os


def print_progress(iteration, total, prefix='', suffix='', decimals=1, bar_length=100):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        bar_length  - Optional  : character length of bar (Int)
    """
    str_format = "{0:." + str(decimals) + "f}"
    percents = str_format.format(100 * (iteration / float(total)))
    filled_length = int(round(bar_length * iteration / float(total)))
    bar = '█' * filled_length + '-' * (bar_length - filled_length)

    sys.stdout.write('\r%s |%s| %s%s %s' % (prefix, bar, percents, '%', suffix)),

    if iteration == total:
        sys.stdout.write('\n')
    sys.stdout.flush()

class lz4decomp(object):
    def lz4_decompress(self,filename,filenameout):
        chunk_size = 1*1024*1024*1024
        filesize=os.stat(filename).st_size
        print_progress(0, 100, prefix='Decompressing: \"%s\"' % filename, suffix='', bar_length=50)
        pos=0
        old=0
        filepos=0
        total=filesize
        with open(filenameout,"wb") as wf:
            with open(filename,'rb') as rf:
                with lz4.frame.LZ4FrameDecompressor() as decompressor:
                    while filepos<total:
                        if filesize < chunk_size:
                            chunk_size = filesize
                        buffer=rf.read(chunk_size)
                        decompressed = decompressor.decompress(buffer)
                        wf.write(decompressed)
                        filepos+=chunk_size
                        pos = int(filepos / total * 100)
                        if pos > old:
                            print_progress(pos, 100, prefix='Decompressing: \"%s\"' % filename, suffix='',
                                           bar_length=50)
                            old = pos

'''
def main(argv):
    if len(argv)<3:
        print("Usage: lz4decomp [infile] [outfile]")
        exit(0)
    print(argv[1])
    lz4decomp().lz4_decompress(argv[1],argv[2])

main(sys.argv)
'''