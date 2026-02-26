import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = searchParams.get('domain');

  if (!domain) {
    return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
  }

  try {
    const res = await fetch(`https://networkcalc.com/api/dns/whois/${domain}`);
    if (!res.ok) {
      throw new Error('Failed to fetch WHOIS data');
    }
    const data = await res.json();
    return NextResponse.json(data);
  } catch (error: any) {
    return NextResponse.json({ error: error.message || 'Failed to fetch WHOIS data' }, { status: 500 });
  }
}
