echo XD
rm -rf node_modules/
cp -rf . ../dist
rm ../dist/flag.txt
mv ../dist/Dockerfile.censored ../dist/Dockerfile
echo ok done