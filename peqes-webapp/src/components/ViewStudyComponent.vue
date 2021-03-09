<template>
    <v-dialog width="1280" v-model="dialog">
        <v-card>
            <v-card-title class="headline grey lighten-2" primary-title>
                <v-icon left v-if="study.status === 'New'">mdi-clock-alert-outline</v-icon>
                <v-icon left v-if="study.status === 'Approved'">mdi-checkbox-marked-circle-outline</v-icon>
                <v-icon left v-if="study.status === 'Completed'">mdi-package-down</v-icon>

                {{ study.name }}
            </v-card-title>

            <v-subheader>Study Information</v-subheader>

            <v-list-item class="ml-5">
                <v-list-item-content>
                    <v-list-item-subtitle>Description</v-list-item-subtitle>
                    <v-list-item-title>{{ study.description }}</v-list-item-title>
                </v-list-item-content>
            </v-list-item>

            <v-list-item class="ml-5" v-if="study.status !== 'New'">
                <v-list-item-content>
                    <v-list-item-subtitle>Response Count</v-list-item-subtitle>
                    <v-list-item-title>{{ study.response_count }}</v-list-item-title>
                </v-list-item-content>
            </v-list-item>

            <v-list-item class="ml-5" v-if="study.status === 'Completed'">
                <v-list-item-content>
                    <v-list-item-subtitle>Analysis Result</v-list-item-subtitle>
                    <v-card flat tile elevation="2" color="grey lighten-3">
                        <v-card-text>
                            <v-sheet class="pa-4">
                                <vue-json-pretty :data="study.result" />
                            </v-sheet>
                        </v-card-text>
                    </v-card>
                </v-list-item-content>
            </v-list-item>

            <v-subheader>Questionnaire</v-subheader>

            <v-list-item class="ml-5">
                <v-list-item-content>
                    <v-tabs background-color="indigo" dark v-model="tab">
                        <v-tab>
                            <v-icon left>mdi-eye-outline</v-icon>
                            Preview
                        </v-tab>
                        <v-tab>
                            <v-icon left>mdi-code-tags</v-icon>
                            Source
                        </v-tab>
                    </v-tabs>

                    <v-tabs-items v-model="tab" style="width: 100%;">
                        <v-tab-item>
                            <v-card flat tile elevation="2" color="grey lighten-3">
                                <v-card-text>
                                    <survey :survey="survey" />
                                </v-card-text>
                            </v-card>
                        </v-tab-item>

                        <v-tab-item>
                            <v-card flat tile elevation="2" color="grey lighten-3">
                                <v-card-text>
                                    <v-sheet class="pa-4">
                                        <vue-json-pretty :data="study.questionnaire" />
                                    </v-sheet>
                                </v-card-text>
                            </v-card>
                        </v-tab-item>
                    </v-tabs-items>
                </v-list-item-content>
            </v-list-item>

            <v-subheader>Analysis</v-subheader>

            <v-list-item class="ml-5">
                <v-list-item-content>
                    <v-sheet class="pa-5" color="grey lighten-3" elevation="2" outlined>
                        <pre style="font-family: monospace; font-size: 10pt;">{{ study.analysis }}</pre>
                    </v-sheet>
                </v-list-item-content>
            </v-list-item>

            <v-subheader>Metadata</v-subheader>

            <v-list-item class="ml-5">
                <v-list-item-content>
                    <v-list-item-subtitle>Enclave Public Key</v-list-item-subtitle>
                    <pre>{{ study.public_key }}</pre>
                </v-list-item-content>
            </v-list-item>

            <v-list-item class="ml-5">
                <v-list-item-content>
                    <v-list-item-subtitle>Researcher Identity</v-list-item-subtitle>
                    <pre>{{ study.researcher_identity }}</pre>
                </v-list-item-content>
            </v-list-item>

            <v-list-item class="ml-5">
                <v-list-item-content>
                    <v-list-item-subtitle>Researcher Signature</v-list-item-subtitle>
                    <pre>{{ study.researcher_signature }}</pre>
                </v-list-item-content>
            </v-list-item>

            <v-list-item class="ml-5">
                <v-list-item-content v-if="study.hash">
                    <v-list-item-subtitle>Study Hash</v-list-item-subtitle>
                    <pre>{{ study.hash }}</pre>
                </v-list-item-content>
            </v-list-item>

            <v-card-actions>
                <v-spacer></v-spacer>
                <slot name="actions"></slot>
            </v-card-actions>
        </v-card>
    </v-dialog>
</template>

<script>
import 'survey-vue/survey.css';
import * as Survey from 'survey-vue';
import VueJsonPretty from 'vue-json-pretty';

export default {
    name: 'ViewStudyComponent',
    
    components: {
        VueJsonPretty
    },

    data: () => ({
        tab: null,
        dialog: false,
        survey: null,
        study: {}
    }),

    methods: {
        async loadStudy(data) {
            this.dialog = false;
            if (data !== null) {
                this.study = data;
                this.dialog = true;
                this.survey = new Survey.Model(this.study.questionnaire);
                if (data.status === 'Completed') {
                    this.study.result = JSON.parse(data.result);
                } else if (!data.status) {
                    this.study.status = 'New';
                }
            }
        },

        close() {
            this.dialog = false;
        }
    }
};
</script>

<style scoped>
.vjs-tree {
    font-size: 10pt;
    line-height: 1.15;
}
</style>
