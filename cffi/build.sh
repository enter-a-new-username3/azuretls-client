system=$(uname)
architecture=$(dpkg --print-architecture)
go build -buildmode=c-shared -o "libazuretls_${system,}_${architecture,}.so"
rm *.h
