import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = searchParams.get('domain');

  if (!domain) {
    return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
  }

  try {
    // Fetch from crt.sh
    const response = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
      headers: {
        'Accept': 'application/json'
      },
      // crt.sh can be slow, but fetch doesn't have a direct timeout option in standard API without AbortController
      // We'll just await it.
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch from crt.sh: ${response.statusText}`);
    }

    const data = await response.json();
    
    const subdomains = new Set<string>();
    if (Array.isArray(data)) {
      data.forEach((entry: any) => {
        if (entry.name_value) {
          const names = entry.name_value.split('\n');
          names.forEach((name: string) => {
            name = name.trim().toLowerCase();
            // Basic filtering
            if (name && name.endsWith(`.${domain}`) && !name.includes('*')) {
              subdomains.add(name);
            }
          });
        }
      });
    }

    return NextResponse.json({ subdomains: Array.from(subdomains) });
  } catch (error: any) {
    console.error('Error fetching subdomains:', error);
    return NextResponse.json({ error: error.message || 'Failed to fetch subdomains' }, { status: 500 });
  }
}
