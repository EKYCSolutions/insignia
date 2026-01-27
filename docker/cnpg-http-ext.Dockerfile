ARG BASE=ghcr.io/cloudnative-pg/postgresql:18-minimal-trixie
FROM $BASE AS builder

ARG PG_MAJOR=18
ARG EXT_VERSION=v1.7.0

USER 0

RUN ldconfig -p | awk '{print $NF}' | grep '^/' | sort | uniq > /tmp/base-image-libs.out &&\
    apt-get update &&\
    apt-get install -y --no-install-recommends git g++ make ca-certificates libcurl4-openssl-dev postgresql-server-dev-${PG_MAJOR} &&\
    git clone --depth 1 --branch ${EXT_VERSION} https://github.com/pramsey/pgsql-http &&\
    cd pgsql-http &&\
    make &&\
    make install &&\
    mkdir -p /system &&\
    ldd /usr/lib/postgresql/18/lib/http.so  | awk '{ print $3 }' | grep '^/' | sort | uniq > /tmp/all-deps.out &&\
    comm -13 /tmp/base-image-libs.out /tmp/all-deps.out > /tmp/libraries.out &&\
    while read -r lib; do \
		resolved=$(readlink -f "$lib"); \
		dir=$(dirname "$lib"); \
		base=$(basename "$lib"); \
		# Copy the real file
		cp -a "$resolved" /system/; \
		# Reconstruct all its symlinks
		for file in "$dir"/"${base%.so*}.so"*; do \
			[ -e "$file" ] || continue; \
			# If it's a symlink and it resolves to the same real file, we reconstruct it
			if [ -L "$file" ] && [ "$(readlink -f "$file")" = "$resolved" ]; then \
				ln -sf "$(basename "$resolved")" "/system/$(basename "$file")"; \
			fi; \
		done; \
	done < /tmp/libraries.out

FROM scratch

ARG PG_MAJOR=18

COPY --from=builder /system /system
COPY --from=builder /usr/lib/postgresql/${PG_MAJOR}/lib/http.so /lib/
COPY --from=builder /usr/lib/postgresql/${PG_MAJOR}/lib/bitcode/ /lib/bitcode/

COPY --from=builder /usr/share/postgresql/${PG_MAJOR}/extension/http* /share/extension/

USER 65532:65532
