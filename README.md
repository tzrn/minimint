# minimint
To run locally on https://127.0.0.1:3000/
```
git clone https://github.com/tzrn/minimint
cd minimint
go build .
mkcert 127.0.0.1
./socialNetwork local
```

To run globally replace minimint.xyz in static/common.js and main.go with your domain and then run
```
./socialNetwork global
```
