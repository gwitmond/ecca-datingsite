
## user setup

useradd -m -U eccadating
usermod -p 'no-password-login' eccadating
passwd -u eccadating

## basic setup

mkdir -p ~/gopath/src
export GOPATH=~/gopath
echo '!!' >> ~/.bashrc

sudo apt-get install golang gcc


## dating site specific
sudo apt-get install libsqlite3-dev sqlite3

cd gopath/src
go get github.com/gwitmond/ecca-datingsite

cd ~gopath/src/gwitmond/ecca-datingsite
# create certificates with util/make-cert.go

# configure ip-addresses in the main.go source code

go run main.go