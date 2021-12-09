import os

dest = "localhost:8080"
len_inbox = 5

for i in range(len_inbox):
    os.system("curl {}/1/inbox/{} --output {}.ctr".format(dest, i, i + 1))
    os.system("go run receiver_decrypt.go {}.ctr".format(i + 1))

print("-" * 120)
for i in range(len_inbox):
    os.system("curl {}/1/inbox/{} --output {}.ctr".format(dest,
                                                          i + len_inbox, i + 1 + len_inbox))
    os.system("go run receiver_decrypt.go {}.ctr".format(i + 1 + len_inbox))
