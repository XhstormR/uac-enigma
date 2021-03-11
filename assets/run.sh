xxd -p payload.raw | tr -d "\n" > payload.txt && split -n 50 -e -d --additional-suffix=.txt payload.txt payload-

# cat payload-*
