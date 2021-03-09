<template>
    <div>
        <v-dialog width="1280" v-model="dialog" @click:outside="close" persistent>
            <v-card>
                <v-card-title class="headline grey lighten-2" primary-title>
                    {{ study.name }}
                </v-card-title>

                <v-card-text class="pt-5">
                    <survey :survey="survey" v-if="survey !== null" />
                </v-card-text>

                <v-divider />

                <v-card-actions>
                    <v-spacer />
                </v-card-actions>
            </v-card>
        </v-dialog>

        <v-dialog width="520" v-model="alert" persistent>
            <v-card>
                <v-card-title class="headline grey lighten-2" primary-title>
                    Do you want to discard your current inputs?
                </v-card-title>

                <v-card-text class="pt-3">
                    You have not submitted your inputs yet.
                    Do you want to exit <b>without</b> submitting the survey?
                </v-card-text>

                <v-card-actions>
                    <v-spacer />
                    <v-btn color="error" text @click="dialog = false; alert = false">Discard Inputs</v-btn>
                    <v-btn color="primary" text @click="alert = false">Cancel</v-btn>
                </v-card-actions>
            </v-card>
        </v-dialog>
    </div>
</template>

<script>
import 'survey-vue/survey.css';
import * as Survey from 'survey-vue';

export default {
  name: 'StudySurveyComponent',

  data: () => ({
    dialog: false,
  alert: false,
    study: {},
    survey: null
  }),

  methods: {
    async loadStudy(id, study) {
      this.dialog = false;
      if (id !== null) {
        this.study = study;
        this.dialog = true;
        this.survey = new Survey.Model(this.study.questionnaire);
        this.survey.onComplete.add(async (result) => {
          this.$emit('completed', id, study, result.data);
          this.dialog = false;
        });
      }
    },

    close() {
        // this.dialog = false;
        this.alert = true;
    }
  }
};
</script>
