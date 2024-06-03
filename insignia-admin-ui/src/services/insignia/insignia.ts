
export interface InsigniaUser {
  id: string;
  name: string;
  email?: string;
  phone?: string;
  phoneVerifiedAt?: Date;
  emailVerifiedAt?: Date;
  extrasMeta: { [key: string]: unknown; };
  webauthnCredentials: { id: string; name: string; }[];
}

export interface InsigniaSetting {
  id: string;
  webhookReceiverUrl?: string;
  webhookReceiverApiKey?: string;
  createdAt: Date;
}

export interface InsigniaLimitOffsetPaging {
  limit: number;
  offset: number;
}

export interface InsigniaSaveSettingRequest {
  webhookReceiverUrl?: string;
  webhookReceiverApiKey?: string;
}

export interface InsigniaWebauthnAllowOrigin {
  id: number;
  origin: string;
  createdAt: Date;
}

export interface InsigniaAddWebauthnAllowOriginRequest {
  origin: string;
}

export interface InsigniaUpdateWellknownsConfigRequest {
  assetlinkAndroidPackageName: string;
  appleAppSiteAssociationIosAppIds: string[];
  assetlinkAndroidSha256Fingerprints: string[];
}

export class InsigniaError extends Error {
  code: string;
  message: string;
  errorDetail?: unknown;

  context?: unknown;

  constructor(code: string, message: string, opts?: { errorDetail?: unknown, context?: unknown; }) {
    super(message);

    this.code = code;
    this.message = message;
    this.context = opts?.context;
    this.errorDetail = opts?.errorDetail;

    Object.setPrototypeOf(this, InsigniaError.prototype);
  }
}

export abstract class InsigniaService {
  abstract removeUser(userId: string): Promise<void>;

  abstract listUsers(_: InsigniaLimitOffsetPaging): Promise<InsigniaUser[]>;

  abstract getSetting(): Promise<InsigniaSetting>;

  abstract saveSetting(_: InsigniaSaveSettingRequest): Promise<void>;

  abstract listWebauthnAllowOrigins(): Promise<InsigniaWebauthnAllowOrigin[]>;

  abstract addWebauthnAllowOrigin(_: InsigniaAddWebauthnAllowOriginRequest): Promise<InsigniaWebauthnAllowOrigin>;

  abstract removeWebauthnAllowOrigin(id: number): Promise<void>;

  abstract updateWellknownsConfig(_: InsigniaUpdateWellknownsConfigRequest): Promise<void>;
}
