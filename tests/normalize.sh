#!/bin/sh
# SPDX-License-Identifier: MIT
# Masks the random fields in sip-golden output so two builds compare byte for byte.
exec sed -E \
	-e 's/branch=z9hG4bK[0-9a-f]+/branch=z9hG4bK<rand>/g' \
	-e 's/tag=(b2q)?[0-9a-f]{8}\b/tag=<rand>/g' \
	-e 's/^(Call-ID: )[0-9a-f]{16,}@/\1<rand>@/' \
	-e 's/^(o=[^ ]+ )[0-9]+ [0-9]+/\1<sess> <ver>/' \
	-e 's/^----- [0-9]+ bytes$/----- <len>/' \
	"$@"
