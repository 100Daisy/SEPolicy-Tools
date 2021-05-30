import os
import shutil
import time

sepolicies = open('fixdenials.txt')
debug = True
policies = 0
audits = 0

try:
  shutil.rmtree('sepolicy')
except:
  pass
os.mkdir('sepolicy')

for line in sepolicies:
   if "#=============" in line:
      policies = policies + 1
      filename = ""
      sepolicy = line[15:]
      for i in sepolicy:
          filename = filename + i
          if i == " ":
              break
      filename = filename[:-1] + ".te"
      sepolicy = open("sepolicy/" + filename, 'x')
   try:
      if "#=============" in line:
         continue
      sepolicy.write(line)
      audits = audits + 1
   except:
      continue
   if debug == True:
      time.sleep(0.1)
      os.system("clear")
      print("Processing: " + filename)
      print("Created " + str(policies) + " policies with " + str(audits) + " audits")
