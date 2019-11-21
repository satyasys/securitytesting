# Retrieve all valid URLs from web.archive.org
#!/bin/bash
if [ $# -ne 1 ]
then
        echo "Usage: ./waybackurl.sh url";
        exit -1;
fi
filename=`echo $1 | cut -d "/" -f1`;
rm ${filename}.json;
rm tmp${filename}.json;
curl -s "http://web.archive.org/cdx/search?url=${1}&matchType=prefix&collapse=urlkey&output=json&fl=original%2Cmimetype%2Ctimestamp%2Cendtimestamp%2Cgroupcount%2Cuniqcount&limit=100000" -o ${filename}.json;
cat ${filename}.json | cut -d '"' -f2 > tmp${filename}.json
while read a;
do
b=`curl -s -o /dev/null -I -w "%{http_code}" $a`;
if [ "$b" != "000" ] && [ "$b" != "503" ]
then
echo "$a $b";
fi
done < tmp${filename}.json | tee -a ${filename}\.archives\.txt;
