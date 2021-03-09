<template>
    <div>
        <view-study-component ref="view">
            <template v-slot:actions>
                <v-btn text color="primary" @click="approve" v-if="data.status === 'New'">
                    <v-icon left>mdi-pencil</v-icon> Approve
                </v-btn>
            </template>
        </view-study-component>

        <AlertsListComponent ref="alerts" />
        <ListStudiesComponent ref="list" @selected="onStudySelected" />

        <v-dialog v-model="approveDialog" persistent max-width="550" v-if="data != null">
            <v-card>
                <v-card-title class="headline">Approve Study: "{{ data.name }}"</v-card-title>

                <v-card-text>
                    Execute the following command with the ethics-client to approve the study:

                    <v-textarea outlined label="Approve Command" prepend-icon="mdi-console" v-model="approveCommand" class="mt-5" style="font-family: monospace; font-size: 10px;" readonly />
                </v-card-text>

                <v-card-actions>
                    <v-spacer></v-spacer>
                    <v-btn color="green darken-1" text @click="onApprovementDone">Done</v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>
    </div>
</template>

<script>
import axios from 'axios';
import crypto from '../plugins/crypto';
import * as stringify from 'json-stable-stringify';

import ViewStudyComponent from '../components/ViewStudyComponent';
import AlertsListComponent from '../components/AlertsListComponent';
import ListStudiesComponent from '../components/ListStudiesComponent';

export default {
    name: 'EthicsBoardView',
    
    components: {
        ViewStudyComponent,
        AlertsListComponent,
        ListStudiesComponent
    },

    data: () => ({
        approveDialog: false,
        approveCommand: '',
        data: {},
        study: null
    }),

    methods: {
        async approve() {
            this.approveDialog = true;
            this.approveCommand = `peqes-client --approve-study ${window.location.href.split('/', 3).join('/')}/api/studies/${this.study} --hash=${this.data.hash}`;
        },

        async onStudySelected(study) {
            const response = await axios.get(`/api/studies/${study}`, { transformResponse: d => d });
            this.data = JSON.parse(response.data);

            if (this.data.status && this.data.status !== 'New') {
                response.data = stringify({
                    analysis: this.data.analysis,
                    description: this.data.description,
                    name: this.data.name,
                    public_key: this.data.public_key,
                    questionnaire: this.data.questionnaire,
                    researcher_identity: this.data.researcher_identity,
                    researcher_signature: this.data.researcher_signature,
                });
            }

            const data = new TextEncoder().encode(response.data);
            const hash = await window.crypto.subtle.digest({ name: 'SHA-256' }, data);
            this.data.hash = crypto.hexEncArr(hash);
            this.study = study;

            this.$refs.view.loadStudy(this.data);
        },

        async onApprovementDone() {
            await this.$refs.list.reload();
            this.approveDialog = false;
            this.$refs.view.close();
        }
    }
};
</script>
