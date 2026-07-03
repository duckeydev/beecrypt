export function base64urlEncode(buf: Uint8Array): string {
  const codes = new Array(buf.length);
  for (let i = 0; i < buf.length; i++) codes[i] = String.fromCharCode(buf[i]);
  return btoa(codes.join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(s: string): Uint8Array {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  
  if (pad === 1) throw new Error("Invalid base64url string");
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  
  const binary = atob(s);
  const buf = new Uint8Array(binary.length);
  
  for (let i = 0; i < binary.length; i++) {
    buf[i] = binary.charCodeAt(i);
  }
  
  return buf;
}
