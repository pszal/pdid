all:
	gcc -w -o local_test local_test.c lib/pdid.c lib/pdid_gpm.c lib/tweetnacl.c lib/randombytes.c lib/ecc.c lib/utils.c
	gcc -w -o integration_test integration_test.c  lib/pdid.c lib/pdid_gpm.c lib/tweetnacl.c lib/randombytes.c lib/ecc.c lib/utils.c

clean:
	rm -rf local_test integration_test
