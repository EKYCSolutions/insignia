
import { InsigniaService } from './insignia/insignia';
import { InsigniaHttp } from './insignia/insignia_http';

export const insignia: InsigniaService = new InsigniaHttp('https://xadminx.identity.lsa.xdevx.dedyn.io');
