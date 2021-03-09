<template>
    <div>
        <CreateStudyComponent @created="onStudyCreated" />
        <ViewStudyComponent ref="view">
            <template v-slot:actions>
                <v-btn text color="primary" @click="complete" v-if="data.status === 'Approved'">
                    <v-icon left>mdi-stop</v-icon> Complete
                </v-btn>
            </template>
        </ViewStudyComponent>

        <ListStudiesComponent ref="list" @selected="onStudySelected" />

        <v-dialog v-model="completeDialog" persistent max-width="550" v-if="data != null">
            <v-card>
                <v-card-title class="headline">Complete Study: "{{ data.name }}"</v-card-title>

                <v-card-text>
                    Are you really certain that you want to complete the study "{{ data.name }}"?
                    This will execute the configured analysis with {{ data.response_count }} responses and cannot be undone!
                </v-card-text>

                <v-card-actions>
                    <v-spacer></v-spacer>
                    <v-btn color="error darken-1" text @click="onComplete">Complete</v-btn>
                    <v-btn color="green darken-1" text @click="completeDialog = false">Cancel</v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>
    </div>
</template>

<script>
import axios from 'axios';

import crypto from '../plugins/crypto';
import CreateStudyComponent from '../components/CreateStudyComponent';
import ListStudiesComponent from '../components/ListStudiesComponent';
import ViewStudyComponent from '../components/ViewStudyComponent';

export default {
    name: 'ResearcherView',

    components: {
        ViewStudyComponent,
        CreateStudyComponent,
        ListStudiesComponent
    },

    data: () => ({
        completeDialog: false,
        data: {},
        study: null
    }),

    methods: {
        onStudyCreated() {
            this.$refs.list.reload();
        },

        complete() {
            this.completeDialog = true;
        },

        async onComplete() {
            this.completeDialog = false;

            const researcherSK = await crypto.getResearcherPrivateKey();
            const data = crypto.base64DecToArr(this.data.public_key);
            const signature = await window.crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, researcherSK, data);
            const asn1 = crypto.signatureToASN1(signature);

            await axios.post(`/api/studies/${this.study}/complete`, { auth: asn1 });
            await this.$refs.list.reload();
            await this.$refs.view.close();
        },

        async onStudySelected(study) {
            const response = await axios.get(`/api/studies/${study}`);
            this.data = response.data;
            this.study = study;
            this.$refs.view.loadStudy(this.data);
        }
    }
};
</script>
