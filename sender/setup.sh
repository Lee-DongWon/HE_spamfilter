export DEBIAN_FRONTEND=noninteractive
export TZ=Asia/Seoul
ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

apt update
apt install golang git curl python3 -y

go get golang.org/x/crypto/blake2b
go get github.com/ldsec/lattigo/v2

cd /root/go/src/github.com/ldsec/
mkdir tmp
mv lattigo tmp
mv tmp lattigo
cd lattigo
mv lattigo v2
cp /home/params.go ./v2/ckks/params.go

