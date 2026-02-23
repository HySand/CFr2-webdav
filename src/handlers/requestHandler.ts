import { Env } from '../types';
import { handleWebDAV } from './webdavHandler';
import { authenticate } from '../utils/auth';
import { setCORSHeaders } from '../utils/cors';
import { logger } from '../utils/logger';

export async function handleRequest(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  try {
    const method = request.method.toUpperCase();
    
    const publicMethods = ["GET", "HEAD", "OPTIONS", "PROPFIND"];
    const isPublic = publicMethods.includes(method);

    if (!isPublic && !authenticate(request, env)) {
      return new Response("Unauthorized", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="WebDAV Write Access"'
        }
      });
    }

    const response = await handleWebDAV(request, env);

    setCORSHeaders(response, request);
    return response;

  } catch (error) {
    logger.error("Error in request handling:", error);
    return new Response("Internal Server Error", { status: 500 });
  }
}
