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

ADVANCED USAGE
--------

SSLCheck can also recoginze [JPX topix data](https://www.jpx.co.jp/markets/statistics-equities/misc/01.html) formatted CSV.


### CSV format

```
日付,コード,銘柄名,市場・商品区分,33業種コード,33業種区分,17業種コード,17業種区分,規模コード,規模区分
```

### usage

```
$ cat data.csv | sslcheck
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


### LICENSE

Licensed under The GPLv3 License
