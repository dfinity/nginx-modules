# This is currently meant to be run manually and not in CI/CD
#
# Needs nginx source code path specified, e.g.
# make NGINX_SRC=~/nginx-1.21.3

NGINX_SRC ?= ~/nginx-1.21.3

all: test_identifier test_process_body

test_identifier:
	@gcc -D__IC_RUN_TESTS -o identifier_test base32.c crc32.c identifier.c identifier_test.c
	@./identifier_test || (echo "TEST FAILED"; exit 1)
	@rm -f identifier_test

test_process_body:
	@gcc -I ${NGINX_SRC}/src/os/unix -I ${NGINX_SRC}/src/core -I ${NGINX_SRC}/objs \
	-D__IC_RUN_TESTS -o process_body_test base32.c crc32.c identifier.c cb0r.c ic.c process_body.c \
	process_body_test.c
	@./process_body_test || (echo "TEST FAILED"; exit 1)
	@rm -f process_body_test
