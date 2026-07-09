export interface SampleBinding {
  identifier: string
  identifier_type: string
  salt_b64u: string
}

export async function loadSample(baseUrl = 'sample/'): Promise<{ bytes: Uint8Array; binding: SampleBinding }> {
  const [bundleRes, bindingRes] = await Promise.all([
    fetch(`${baseUrl}demo.attest`),
    fetch(`${baseUrl}demo-binding.json`),
  ])
  if (!bundleRes.ok || !bindingRes.ok) throw new Error('sample assets are missing from this deployment')
  return {
    bytes: new Uint8Array(await bundleRes.arrayBuffer()),
    binding: (await bindingRes.json()) as SampleBinding,
  }
}
