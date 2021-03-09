<template>
  <div>
    <AlertsListComponent ref="alerts" />
    <StudySurveyComponent ref="survey" @completed="onStudyCompleted" />
    <ListStudiesComponent @selected="onStudySelected" filter="Approved" />
  </div>
</template>

<script>
import axios from 'axios';
import crypto from '../plugins/crypto';

import AlertsListComponent from '../components/AlertsListComponent';
import StudySurveyComponent from '../components/StudySurveyComponent';
import ListStudiesComponent from '../components/ListStudiesComponent';

export default {
  name: 'ParticipantView',

  components: {
    AlertsListComponent,
    StudySurveyComponent,
    ListStudiesComponent
  },

  methods: {
    async onStudySelected(study) {
      const response = await axios.get(`/api/studies/${study}`);
      this.$refs.survey.loadStudy(study, response.data);
    },

    async onStudyCompleted(id, study, data) {
      try {
        console.log(id, study, data);
        // todo verify certificate

        const response = await axios.post(`/api/studies/${id}`, {});
        const submissionId = response.data.id;

        // const signature = crypto.base64DecToArr(response.data.signature);
        // todo verify signature

        const key = await window.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']);
        const ownPublicKey = new Uint8Array(await window.crypto.subtle.exportKey('raw', key.publicKey));
        const peqesPublicKey = crypto.base64DecToArr(response.data.pk);

        const info = new Uint8Array(130);
        info.set(peqesPublicKey, 0);
        info.set(ownPublicKey, 65);

        const pk = await window.crypto.subtle.importKey('raw', peqesPublicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
        const keyMaterial = await window.crypto.subtle.deriveBits({ name: 'ECDH', namedCurve: 'P-256', public: pk }, key.privateKey, 256);
        const derivedKey = await window.crypto.subtle.importKey('raw', keyMaterial, { name: 'HKDF' }, false, ['deriveKey']);

        const sharedKey = await window.crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-512', salt: new Uint8Array(), info: info }, derivedKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
        const nonce = window.crypto.getRandomValues(new Uint8Array(12));
        const plaintext = new TextEncoder().encode(JSON.stringify(data));
        const encrypted = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, sharedKey, plaintext);

        const submission = await axios.put(`/api/studies/${id}/${submissionId}`, {
            pk: crypto.base64EncArr(ownPublicKey),
            response: crypto.base64EncArr(new Uint8Array(encrypted)),
            nonce: crypto.base64EncArr(nonce)
        });

        if (submission.data.ok !== true) {
            throw new '';
        }

        this.$refs.alerts.add('success', 'Successfully submitted response!');
      } catch {
        this.$refs.alerts.add('error', 'An error occured while submitting response.');
      }
    }
  }
};
</script>
