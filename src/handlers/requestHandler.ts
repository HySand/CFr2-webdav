import { Env } from '../types';
import { handleWebDAV } from './webdavHandler';
import { authenticate } from '../utils/auth';
import { setCORSHeaders } from '../utils/cors';
import { logger } from '../utils/logger';

export async function handleRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
    const method = request.method.toUpperCase();
    const pathname = url.pathname;

    const isPublicPath = pathname.startsWith("/public/");

    const readOnlyMethods = ["GET", "HEAD", "OPTIONS", "PROPFIND"];
    const isReadOnly = readOnlyMethods.includes(method);
    
    let authorized = false;

    if (isPublicPath && isReadOnly) {
      authorized = true;
    } else {
      authorized = authenticate(request, env);
    }

    if (!authorized) {
      return new Response("Unauthorized: Private area or restricted operation", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="WebDAV Private Storage"',
        },
      });
    }

    const response = await handleWebDAV(request, env);
    setCORSHeaders(response, request);
    return response;

  } catch (error) {
    logger.error("Gateway Error:", error);
    return new Response("Internal Server Error", { status: 500 });
  }
}
