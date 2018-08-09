# SSLCheck

SSLCheck is a simple command line tool to verify ssl certificate written in golang.

INSTALLATION
------------

```
$ go get github.com/feedtailor/SSLCheck
$ go build -o sslcheck github.com/feedtailor/SSLCheck
```

USAGE
-----

### one site

```
$ echo "http://example.com/" | sslcheck
```

### two or more sites

```
$ cat sites.txt
http://example.com/
https://example.org/

$ cat sites.txt | sslcheck
```

OUTPUT
------

SSLCheck output the tab-delimited text to STDOUT.
```
http://example.com/	https://example.com/	200	www.example.org	US	Los Angeles	Internet Corporation for Assigned Names and Numbers	Technology	DigiCert SHA2 High Assurance Server CA	DigiCert Inc	2015/11/03 - 2018/11/28	OV
```
- original URL
- verified URL
- HTTP status
- Common name
- Country
- Locality
- Organization
- Organizational Unit
- Issuer's common name
- Issuer's organization
- Validity
- Type of certificate


LICENSE
-------

Licensed under The GPLv3 License
