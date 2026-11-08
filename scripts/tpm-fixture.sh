#!/bin/sh
# Run inside a disposable Debian bookworm container with swtpm, tpm2-tools, openssl and python3.
# Usage: sh /scripts/tpm-fixture.sh /output (output must not exist).
set -eu
out=${1:?output directory required}
case "$out" in /*) ;; *) printf '%s\n' 'output must be absolute' >&2; exit 1;; esac
mkdir "$out"
work=$(mktemp -d)
trap 'if [ -f "$work/swtpm.pid" ]; then kill "$(python3 -I -c "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text().strip())" "$work/swtpm.pid")" 2>/dev/null || true; fi; rm -rf "$work"' EXIT
mkdir "$work/state"
swtpm socket --tpm2 --tpmstate dir="$work/state" --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init --pid file="$work/swtpm.pid" --daemon
export TPM2TOOLS_TCTI=swtpm:host=127.0.0.1,port=2321
tpm2_startup -c
# Fresh simulator only: these persistent handles belong exclusively to this run.
tpm2_createprimary -C o -G rsa2048:rsassa-sha256:null -g sha256 -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign' -c "$work/ak.ctx"
tpm2_evictcontrol -C o -c "$work/ak.ctx" 0x81010001
tpm2_flushcontext -t
tpm2_createprimary -C o -G rsa2048:rsassa-sha256:null -g sha256 -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -c "$work/key.ctx"
tpm2_evictcontrol -C o -c "$work/key.ctx" 0x81010002
tpm2_flushcontext -t
tpm2_readpublic -c 0x81010001 -f tss -o "$out/ak-public.tpm2b"
tpm2_readpublic -c 0x81010001 -f pem -o "$out/ak-public.pem"
tpm2_readpublic -c 0x81010002 -f tss -o "$out/key-public.tpm2b"
tpm2_readpublic -c 0x81010002 -f pem -o "$out/key-public.pem"
openssl pkey -pubin -in "$out/key-public.pem" -outform DER -out "$out/spki.der"
nonce='openwarp-swtpm-interoperability-fixture-v1'
q=$(python3 -I -c 'import hashlib,pathlib,sys; print(hashlib.sha256(b"OpenWarp/TPM2/enroll/v1\0"+sys.argv[2].encode()+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).digest()).hexdigest())' "$out/spki.der" "$nonce")
# tpm2-tools 5.4 certify has no qualifyingData option. Send TPM2_Certify (0x148)
# with two empty password sessions; only command/response framing is assembled here.
python3 -I - "$work/certify.command" "$q" <<'PY'
import pathlib, struct, sys
u16=lambda n: struct.pack('>H', n)
u32=lambda n: struct.pack('>I', n)
auth=u32(0x40000009)+u16(0)+b'\0'+u16(0)
params=u16(32)+bytes.fromhex(sys.argv[2])+u16(0x0014)+u16(0x000b)
body=u32(0x81010002)+u32(0x81010001)+u32(2*len(auth))+auth+auth+params
pathlib.Path(sys.argv[1]).write_bytes(u16(0x8002)+u32(10+len(body))+u32(0x148)+body)
PY
python3 -I - "$work/certify.command" "$work/certify.response" <<'PY'
import pathlib, subprocess, sys, time
for attempt in range(10):
    subprocess.run(['tpm2_send','-o',sys.argv[2],sys.argv[1]],check=True)
    response=pathlib.Path(sys.argv[2]).read_bytes()
    if int.from_bytes(response[6:10],'big') != 0x922:
        break
    time.sleep(0.1)
else:
    raise RuntimeError('TPM2_Certify exhausted TPM_RC_RETRY responses')
PY
python3 -I - "$work/certify.response" "$out" <<'PY'
import pathlib, struct, sys
b=pathlib.Path(sys.argv[1]).read_bytes(); out=pathlib.Path(sys.argv[2])
tag,size,rc=struct.unpack('>HII', b[:10])
assert rc == 0, f'TPM2_Certify response code {rc:#x}'
assert tag == 0x8002 and size == len(b)
n=struct.unpack('>I', b[10:14])[0]; params=b[14:14+n]
a=struct.unpack('>H', params[:2])[0]
attest=params[2:2+a]; sig=params[2+a:]
assert attest[:4] == bytes.fromhex('ff544347')
assert sig[:6] == bytes.fromhex('0014000b0100') and len(sig)==262
(out/'certify.attest').write_bytes(attest)
(out/'certify.signature').write_bytes(sig)
PY
tpm2_quote -c 0x81010001 -l sha256:0,1,2,3,4,5,6,7 -q "$q" -g sha256 -f tss -m "$out/quote.attest" -s "$out/quote.signature" -o "$work/pcrs.tss"
tpm2_pcrread sha256:0,1,2,3,4,5,6,7 -o "$out/pcrs.bin" -F values
tpm2_checkquote -u "$out/ak-public.pem" -m "$out/quote.attest" -s "$out/quote.signature" -f "$work/pcrs.tss" -g sha256 -q "$q"
tpm2_verifysignature -c 0x81010001 -g sha256 -m "$out/certify.attest" -s "$out/certify.signature" -t "$work/verified.ticket"
python3 -I - "$out" "$nonce" "$q" <<'PY'
import base64, hashlib, json, pathlib, struct, subprocess, sys
out=pathlib.Path(sys.argv[1]); nonce=sys.argv[2]; q=sys.argv[3]
b64=lambda b: base64.b64encode(b).decode('ascii')
fields={'ak_public':'ak-public.tpm2b','key_public':'key-public.tpm2b','certify':'certify.attest','certify_signature':'certify.signature','quote':'quote.attest','quote_signature':'quote.signature'}
evidence={k:b64((out/v).read_bytes()) for k,v in fields.items()}
pcrs=(out/'pcrs.bin').read_bytes(); assert len(pcrs)==256
evidence['pcrs']=[b64(pcrs[i:i+32]) for i in range(0,256,32)]
clocks={}
for name in ('certify','quote'):
    b=(out/(name+'.attest')).read_bytes()
    assert b[:4] == bytes.fromhex('ff544347')
    pos=6
    for _ in range(2):
        n=struct.unpack('>H',b[pos:pos+2])[0]; pos+=2
        value=b[pos:pos+n]; pos+=n
    assert value.hex()==q
    clock,reset,restart,safe,firmware=struct.unpack('>QIIBQ',b[pos:pos+25])
    clocks[name]={'clock':clock,'reset_count':reset,'restart_count':restart,'safe':bool(safe),'firmware_version':firmware}
    assert safe==1, f'{name}: simulator reported unsafe clock; do not alter attestation'
for filename in ('ak-public.tpm2b','key-public.tpm2b'):
    b=(out/filename).read_bytes(); assert int.from_bytes(b[:2],'big')==len(b)-2
(out/'evidence.json').write_text(json.dumps(evidence,indent=2)+'\n')
(out/'ak-public.b64').write_text(evidence['ak_public']+'\n')
manifest={'origin':'swtpm software TPM, not physical hardware','nonce':nonce,'qualifying_data_hex':q,'binding':'SHA256(OpenWarp/TPM2/enroll/v1\\0 || nonce UTF8 || SHA256(spki.der))','expected_pcr_digest':hashlib.sha256(pcrs).hexdigest(),'pcr_bank':'sha256','pcr_indices':list(range(8)),'clocks':clocks,'trust':'Test-only operator pin is ak-public.b64, provisioned separately from evidence. Production requires an out-of-band authenticated AK public pin. No EK or hardware provenance proof.','checks':{'tpm2_checkquote':0,'tpm2_verifysignature_certify':0},'tools':subprocess.check_output(['dpkg-query','-W','swtpm','tpm2-tools','libtpms0','libtss2-esys-3.0.2-0','openssl'],text=True).splitlines(),'generation':'scripts/tpm-fixture.sh; fresh simulator; RSA2048 RSASSA SHA256; raw TPMS_ATTEST, TPMT_SIGNATURE, TPM2B_PUBLIC','sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.iterdir()) if p.is_file()}}
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'expected_pcr_digest':manifest['expected_pcr_digest'],'clocks':clocks,'public_files':len(list(out.iterdir()))},indent=2))
PY
