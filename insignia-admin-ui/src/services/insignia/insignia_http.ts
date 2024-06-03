
import ky, { type KyResponse } from 'ky';

import {
  InsigniaError,
  InsigniaService,
  type InsigniaUser,
  type InsigniaSetting,
  type InsigniaLimitOffsetPaging,
  type InsigniaSaveSettingRequest,
  type InsigniaWebauthnAllowOrigin,
  type InsigniaUpdateWellknownsConfigRequest,
  type InsigniaAddWebauthnAllowOriginRequest,
} from './insignia';

export class InsigniaHttp implements InsigniaService {
  private serverUrl: string;

  constructor(serverUrl: string) {
    this.serverUrl = serverUrl;
  }

  async constructError(response: KyResponse, context: unknown) {
    try {
      const errorResp = await response.json() as { code: string; message: string; };

      return new InsigniaError(errorResp.code, errorResp.message, {});
    } catch (error) {
      return new InsigniaError('99', 'unexpected error', { errorDetail: error, context });
    }
  }

  async removeUser(userId: string): Promise<void> {
    const response = await ky.delete(`${this.serverUrl}/users/${userId}`);

    if (response.ok) {
      return;
    }

    const error = await this.constructError(response, { userId });

    throw error;
  }

  async listUsers({ limit, offset }: InsigniaLimitOffsetPaging): Promise<InsigniaUser[]> {
    const response = await ky.get(`${this.serverUrl}/users`, { searchParams: { limit, offset } });

    if (response.ok) {
      const users = await response.json();

      return users.map((u: any) => ({
        id: u.id,
        name: u.name,
        email: u.email,
        phone: u.phone,
        extrasMeta: u.extras_meta,
        emailVerifiedAt: u.email_verified_at,
        phoneVerifiedAt: u.phone_verified_at,
        webauthnCredentials: u.webauthn_credentials.map((wc: any) => ({ id: wc.id, name: wc.name })),
      }));
    }

    const error = await this.constructError(response, { limit, offset });

    throw error;
  }

  getSetting(): Promise<InsigniaSetting> {
    throw new Error('Method not implemented.');
  }

  saveSetting(_: InsigniaSaveSettingRequest): Promise<void> {
    throw new Error('Method not implemented.');
  }

  listWebauthnAllowOrigins(): Promise<InsigniaWebauthnAllowOrigin[]> {
    throw new Error('Method not implemented.');
  }

  addWebauthnAllowOrigin(_: InsigniaAddWebauthnAllowOriginRequest): Promise<InsigniaWebauthnAllowOrigin> {
    throw new Error('Method not implemented.');
  }

  removeWebauthnAllowOrigin(id: number): Promise<void> {
    throw new Error('Method not implemented.');
  }

  updateWellknownsConfig(_: InsigniaUpdateWellknownsConfigRequest): Promise<void> {
    throw new Error('Method not implemented.');
  }
}
