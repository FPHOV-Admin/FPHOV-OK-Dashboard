export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // 1. BACKEND HANDLER: Processes the secure user verification request
    if (url.pathname === '/api/login' && request.method === 'POST') {
      try {
        const { user, pass } = await request.json();

        if (!user || !pass) {
          return new Response(JSON.stringify({ error: 'Missing fields' }), { status: 400 });
        }

        const normalizedUser = user.toLowerCase().trim();

        // 🔐 QUERIES CLOUDFLARE SECURE STORAGE: Pulls your entries by Key name
        const userDataStr = await env.FPHOV_AUTH.get(normalizedUser);
        
        if (!userDataStr) {
          return new Response(JSON.stringify({ error: 'Access Denied' }), { status: 401 });
        }

        const userData = JSON.parse(userDataStr);

        // Validates passwords and active account state parameters matching
        if (userData.password === pass && userData.active === true) {
          console.log(`[AUDIT LOG] Success login: ${normalizedUser}`);

          return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: {
              'Content-Type': 'application/json',
              'Set-Cookie': 'fphov_session=authenticated_user; Path=/; HttpOnly; SameSite=Strict; Secure'
            }
          });
        }

        return new Response(JSON.stringify({ error: 'Access Denied' }), { status: 401 });
      } catch (err) {
        return new Response(JSON.stringify({ error: 'Server Error' }), { status: 500 });
      }
    }

    // 2. BACKEND HANDLER: Route Interception Gatekeeper
    // Allow public access to the login layout card assets automatically
    if (
      url.pathname === '/' || 
      url.pathname === '/index.html' || 
      url.pathname === '/bandit-background.jpg' || 
      url.pathname === '/fphov-logo.png'
    ) {
      return env.ASSETS ? env.ASSETS.fetch(request) : fetch(request);
    }

    // Shield internal planning elements from unauthenticated drops
    const cookieHeader = request.headers.get('Cookie') || '';
    const hasSession = cookieHeader.includes('fphov_session=authenticated_user');

    if (!hasSession) {
      // Re-route drops straight out to the login interface
      return new Response(null, {
        status: 302,
        headers: { 'Location': '/' }
      });
    }

    // Authenticated session validation confirmed, load site layout sheets cleanly
    return env.ASSETS ? env.ASSETS.fetch(request) : fetch(request);
  }
};
