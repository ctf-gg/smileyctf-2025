`build/` contains build scripts for local testing and the qemu patch.

you can run the challenge in docker with:

```sh
docker build . -t test && docker run --rm -p 5000:5000 --privileged -it test
```

note that if you wish to debug qemu you may have to do so outside of redpwn jail.
