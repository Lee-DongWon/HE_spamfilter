import os
import random

dest = "147.46.78.26:8080"
#dest = "localhost:8080"
len_inbox = 5

os.system("curl {}/1/pk --output 1.pk".format(dest))

spam_index = [random.randrange(17170) + 1 for _ in range(len_inbox)]
ham_index = [random.randrange(16545) + 1 for _ in range(len_inbox)]

for i in ham_index:
    os.system("go run sender.go 1.pk ham {}".format(i))
    os.system('curl -X POST -F "ct=@ct" {}/1/send'.format(dest))

print("-" * 120)
for i in spam_index:
    os.system("go run sender.go 1.pk spam {}".format(i))
    os.system('curl -X POST -F "ct=@ct" {}/1/send'.format(dest))
