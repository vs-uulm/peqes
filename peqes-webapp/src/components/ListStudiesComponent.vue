<template>
    <v-list three-line>
        <v-list-item :key="id" @click="selectStudy(id)" v-for="(study, id) in filteredStudies">
            <v-list-item-avatar>
                <v-icon v-show="study.status === 'New'">mdi-clock-alert-outline</v-icon>
                <v-icon v-show="study.status === 'Approved'">mdi-checkbox-marked-circle-outline</v-icon>
                <v-icon v-show="study.status === 'Completed'">mdi-package-down</v-icon>
            </v-list-item-avatar>

            <v-list-item-content>
                <v-list-item-title>{{ study.name }}</v-list-item-title>
                <v-list-item-subtitle>{{ study.description }}</v-list-item-subtitle>
            </v-list-item-content>
        </v-list-item>
    </v-list>
</template>

<script>
import axios from 'axios';

export default {
    name: 'ListStudiesComponent',

    data: () => ({
        studies: {}
    }),

    props: ['filter'],

    async mounted() {
        return this.reload();
    },

    computed: {
        filteredStudies() {
            return Object.fromEntries(Object.entries(this.studies).filter(([, study]) => {
                if (!this.filter) {
                    return true;
                }

                return study.status === this.filter;
            }));
        }
    },

    methods: {
        selectStudy(studyId) {
            this.$emit('selected', studyId);
        },

        async reload() {
            const response = await axios.get('/api/studies');
            this.studies = response.data;
        }
    }
};
</script>
