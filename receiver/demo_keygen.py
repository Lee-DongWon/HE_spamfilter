import os

dest = "localhost:8080"

os.system('curl {}/flush'.format(dest))

os.system("go run receiver_keygen.go")
os.system('curl -X POST -F "pk=@pk" {}/1/pk'.format(dest))
os.system('curl -X POST -F "rek=@rek" {}/1/rek'.format(dest))
os.system('curl -X POST -F "rok=@rok" {}/1/rok'.format(dest))
