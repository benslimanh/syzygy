/***************************************************************************
 *                                                                         *
 *   ____ ___  _ ____ ___  _ ________  _                                   *
 *  / ___\\  \///_   \\  \///  __/\  \//                                   *
 *  |    \ \  /  /   / \  / | |  _ \  /                                    *
 *  \___ | / /  /   /_ / /  | |_// / /                                     *
 *  \____//_/   \____//_/   \____\/_/                                      *
 *                                                                         *
 *  Syzygy                                                                 *
 *                                                                         *
 *  Created by Hamza Bensliman <benslimanh> for 2026                       *
 *                                                                         *
 *  This software is licensed under the terms of the MIT license.          *
 *  You may use, copy, modify, merge, publish, distribute and/or sell      *
 *  copies of the Software, and permit persons to whom the Software is     *
 *  furnished to do so, under the terms of the MIT license.                *
 *                                                                         *
 *  This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF  *
 *  ANY KIND, either express or implied.                                   *
 *                                                                         *
 ***************************************************************************/

import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  scenarios: {
    active: {
      executor: 'constant-vus',
      vus: 50,
      duration: '20s',
      gracefulStop: '5s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.001'],
    http_req_duration: ['p(95)<50'],
  },
  noConnectionReuse: false,
};

// absolute paths for k6 (it runs from the cwd passed)
const URLS = [
  '/ok.txt',
  '/index.html',
  '/payload_1k.bin',
  '/healthz',
  '/payload_16k.bin',
];

const BASE = 'http://127.0.0.1:18080';

export default function () {
  let url = BASE + URLS[Math.floor(Math.random() * URLS.length)];
  let res = http.get(url);
  check(res, { 'status 200': (r) => r.status === 200 });
}
