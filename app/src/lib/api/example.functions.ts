import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";

import { bindings } from "../bindings.server";

// Example server function that touches the app's D1 binding (server-only).
export const getGreeting = createServerFn({ method: "POST" })
  .validator(z.object({ name: z.string().min(1) }))
  .handler(async ({ data }) => {
    const { HF_ENV } = bindings();
    // This is a sample endpoint; configure a Vercel-compatible database separately
    // if a persistent count is needed.
    return { greeting: `Hello, ${data.name}!`, env: HF_ENV ?? "production", count: 0 };
  });
