import http from 'k6/http';
import { sleep, check } from 'k6';

export let options = {
  vus: 10, // virtual users
  duration: '30s', // lama uji
};

export default function () {
  let res = http.get('https://whoami.hae-meto-kreatif.my.id/');
  check(res, { 'status 200': (r) => r.status === 200 });
  sleep(1);
}
