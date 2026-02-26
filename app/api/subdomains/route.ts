import { NextResponse } from 'next/server';
import dns from 'dns';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const domain = searchParams.get('domain');

  if (!domain) {
    return NextResponse.json({ error: 'Domain is required' }, { status: 400 });
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      try {
        const response = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
          headers: {
            'Accept': 'application/json'
          }
        });

        if (!response.ok) {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ error: `Failed to fetch from crt.sh: ${response.statusText}` })}\n\n`));
          controller.close();
          return;
        }

        const reader = response.body?.getReader();
        if (!reader) {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify({ error: 'Failed to read response body' })}\n\n`));
          controller.close();
          return;
        }

        const decoder = new TextDecoder();
        let buffer = '';
        const subdomains = new Set<string>();

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          
          buffer += decoder.decode(value, { stream: true });
          
          // Extract "name_value":"..." from the streaming JSON buffer
          const regex = /"name_value":"([^"]+)"/g;
          let match;
          let newSubdomains: string[] = [];
          
          while ((match = regex.exec(buffer)) !== null) {
            const names = match[1].split('\\n');
            names.forEach((name: string) => {
              name = name.trim().toLowerCase();
              if (name && name.endsWith(`.${domain}`) && !name.includes('*') && !subdomains.has(name)) {
                subdomains.add(name);
                newSubdomains.push(name);
              }
            });
          }
          
          if (newSubdomains.length > 0) {
            // Resolve IPs concurrently
            const resolved = await Promise.all(newSubdomains.map(async (sub) => {
              try {
                const records = await dns.promises.resolve4(sub);
                return { host: sub, ip: records[0] };
              } catch (e) {
                return { host: sub, ip: null };
              }
            }));
            controller.enqueue(encoder.encode(`data: ${JSON.stringify({ subdomains: resolved })}\n\n`));
          }
          
          // Keep a small part of the buffer to handle chunks split across "name_value"
          if (buffer.length > 5000) {
            buffer = buffer.slice(-5000);
          }
        }

        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ done: true })}\n\n`));
        controller.close();
      } catch (error: any) {
        console.error('Error fetching subdomains:', error);
        controller.enqueue(encoder.encode(`data: ${JSON.stringify({ error: error.message || 'Failed to fetch subdomains' })}\n\n`));
        controller.close();
      }
    }
  });

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    },
  });
}
