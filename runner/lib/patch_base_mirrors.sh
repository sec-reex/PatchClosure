#!/bin/bash
set -u
# NOTE: docker commit copies the RUNNING CONTAINER's config (entrypoint/cmd)
# into the committed image — the throwaway `--entrypoint sh -c sleep 300`
# used for the setup lifecycle would be baked in, breaking every image built
# FROM the base at runtime (app CMD executed as `sh /bin/sh -c ...` -> syntax
# error -> exit 2). The original entrypoint/cmd are restored in the commit.
patch_one() { # <img> <setup-cmd>
  local img="$1" setup="$2" cid
  local orig_ep orig_cmd
  orig_ep="$(docker image inspect "$img" --format '{{json .Config.Entrypoint}}')"
  orig_cmd="$(docker image inspect "$img" --format '{{json .Config.Cmd}}')"
  cid=$(docker run -d --entrypoint sh "$img" -c "sleep 300" 2>/dev/null) || { echo "SKIP $img (no sh)"; return; }
  docker exec "$cid" sh -c "$setup" >/dev/null 2>&1 || { docker rm -f "$cid" >/dev/null; echo "SKIP $img (setup)"; return; }
  docker commit --change "ENTRYPOINT $orig_ep" --change "CMD $orig_cmd" \
    "$cid" "$img" >/dev/null 2>&1 && echo "PATCHED $img"
  docker rm -f "$cid" >/dev/null 2>&1
}
M2='<settings><mirrors><mirror><id>aliyun</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/public</url></mirror></mirrors></settings>'
while read img; do
  case "$img" in
    maven:*|gradle:*)
      patch_one "$img" "mkdir -p /root/.m2 && echo '$M2' > /root/.m2/settings.xml" ;;
    node:*)
      patch_one "$img" "mkdir -p /usr/etc /root && echo 'registry=https://registry.npmmirror.com' > /usr/etc/npmrc && cp /usr/etc/npmrc /root/.npmrc" ;;
    python:*)
      patch_one "$img" "printf '[global]\nindex-url = https://mirrors.aliyun.com/pypi/simple/\ntrusted-host = mirrors.aliyun.com\n' > /etc/pip.conf" ;;
    golang:*)
      cid=$(docker run -d --entrypoint sh "$img" -c "sleep 300" 2>/dev/null) || continue
      docker commit --change 'ENV GOPROXY=https://goproxy.cn,direct' \
        --change "ENTRYPOINT $(docker image inspect "$img" --format '{{json .Config.Entrypoint}}')" \
        --change "CMD $(docker image inspect "$img" --format '{{json .Config.Cmd}}')" \
        "$cid" "$img" >/dev/null 2>&1 && echo "PATCHED $img (goproxy)"
      docker rm -f "$cid" >/dev/null 2>&1 ;;
    alpine:*)
      patch_one "$img" "sed -i 's#dl-cdn.alpinelinux.org#mirrors.ustc.edu.cn#g' /etc/apk/repositories" ;;
    ruby:*)
      # ruby-china's TLS handshake fails from this network — TUNA is reliable
      patch_one "$img" "printf -- '---\n:sources:\n- https://mirrors.tuna.tsinghua.edu.cn/rubygems/\n' > /root/.gemrc" ;;
  esac
done < <(docker images --format '{{.Repository}}:{{.Tag}}' | grep -E '^(maven|gradle|node|python|golang|alpine|ruby):')
echo PATCH-BASES-DONE
