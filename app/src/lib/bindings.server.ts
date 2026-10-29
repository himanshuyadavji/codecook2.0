// Vercel-compatible server configuration. Cloudflare-specific D1/R2/KV bindings
// are not available on Vercel; configure ordinary server environment variables
// in the Vercel project settings instead.
type AppEnv = {
  HF_ENV?: string;
  APP_SLUG?: string;
};

export function bindings(): AppEnv {
  return {
    HF_ENV: process.env.HF_ENV,
    APP_SLUG: process.env.APP_SLUG,
  };
}
