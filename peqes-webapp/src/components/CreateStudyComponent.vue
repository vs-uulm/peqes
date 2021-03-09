<template>
    <v-dialog width="1280" v-model="dialog">
        <template v-slot:activator="{ on }">
            <v-btn fixed dark fab bottom right color="green" v-on="on">
                <v-icon>mdi-plus</v-icon>
            </v-btn>
        </template>

        <v-card>
            <v-card-title class="headline grey lighten-2" primary-title>
                Create New Study
            </v-card-title>

            <v-card-text class="pt-5">
                <v-alert type="error" v-show="axiosError">{{ axiosError }}</v-alert>

                <v-list subheader>
                    <v-subheader>Study Information</v-subheader>

                    <v-list-item>
                        <v-list-item-content>
                            <v-text-field v-model="json.name" label="Name" required />
                        </v-list-item-content>
                    </v-list-item>

                    <v-list-item>
                        <v-list-item-content>
                            <v-textarea v-model="json.description" label="Description" required rows="3" />
                        </v-list-item-content>
                    </v-list-item>

                    <v-subheader>Questionnaire</v-subheader>

                    <v-list-item>
                        <v-list-item-content>
                            <v-tabs background-color="indigo" dark v-model="tab">
                                <v-tab>
                                    <v-icon left>mdi-pencil</v-icon>
                                    Edit
                                </v-tab>
                                <v-tab>
                                    <v-icon left>mdi-eye-outline</v-icon>
                                    Preview
                                </v-tab>
                            </v-tabs>

                            <v-tabs-items v-model="tab" style="width: 100%;">
                                <v-tab-item>
                                    <v-jsoneditor v-model="json.questionnaire" :plus="false" height="400px" @error="jsonError = true" @input="jsonError = false; axiosError = false" />
                                </v-tab-item>

                                <v-tab-item>
                                    <survey :survey="survey" />
                                </v-tab-item>
                            </v-tabs-items>
                        </v-list-item-content>
                    </v-list-item>

                    <v-subheader>Analysis</v-subheader>

                    <v-list-item>
                        <v-list-item-content>
                            <v-textarea v-model="json.analysis" label="Analysis Script" style="font-family: monospace; font-size: 10pt;" required filled solo rows="12" />
                        </v-list-item-content>
                    </v-list-item>
                </v-list>
            </v-card-text>

            <v-divider />

            <v-card-actions>
                <v-spacer></v-spacer>
                <v-btn color="primary" text @click="saveStudy()" :disabled="jsonError">Create</v-btn>
            </v-card-actions>
        </v-card>
    </v-dialog>
</template>

<script>
import 'survey-vue/survey.css';
import * as Survey from 'survey-vue';
import * as stringify from 'json-stable-stringify';
import axios from 'axios';
import VJsoneditor from 'v-jsoneditor';
import crypto from '../plugins/crypto.js';

const studyExample = {
    name: 'Example Survey',
    description: 'Simple example that computes the average age of participants',
    questionnaire: {
        title: 'Example Survey',
        pages: [{
            questions: [{
                type: 'text',
                inputType: 'number',
                name: 'age',
                title: 'How old are you?',
                isRequired: true,
                validators: [{
                    type: 'numeric',
                    minValue: 1,
                    maxValue: 100
                }]
            }]
        }]
    },
    analysis: 'pushResult(jStat.mean(data.map(row => row.age)))'
};

export default {
    name: 'CreateStudyComponent',

    components: {
        VJsoneditor
    },

    data: () => ({
        dialog: false,
        jsonError: false,
        axiosError: '',
        tab: null,
        survey: null,
        json: JSON.parse(JSON.stringify(studyExample))
    }),

    watch: {
        tab(tab) {
            if (tab === 1) {
                this.survey = new Survey.Model(this.json.questionnaire);
            }
        },

        dialog(dialog) {
            if (!dialog) {
                // reset form
                this.tab = null;
                this.survey = null;
                this.jsonError = false;
                this.axiosError = '';
                this.json = JSON.parse(JSON.stringify(studyExample));
            }
        }
    },

    methods: {
        async saveStudy() {
            try {
                this.jsonError = true;

                const researcherSK = await crypto.getResearcherPrivateKey();
                const data = new TextEncoder().encode(stringify(this.json));
                const signature = await window.crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, researcherSK, data);
                const asn1 = crypto.signatureToASN1(signature);

                const study = { ...this.json };
                study.researcher_identity = await crypto.getResearcherPublicKey();
                study.researcher_signature = asn1;

                const res = await axios.post('/api/studies', study);
                this.$emit('created', res.data.id);
                this.dialog = false;
            } catch (e) {
                this.axiosError = e.message;
                this.jsonError = false;
            }
        }
    }
};
</script>
