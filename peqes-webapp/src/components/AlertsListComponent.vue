<template>
  <div>
    <v-alert :type="alert.type" v-for="(alert, id) in alerts" :key="id" dismissible>
        {{ alert.text }}
    </v-alert>
  </div>
</template>

<script>
export default {
    name: 'ViewStudyComponent',
    
    data: () => ({
        alerts: []
    }),

    methods: {
        add(type, text, timeout = 5000) {
            const alert = { type, text };
            this.alerts.push(alert);
            setTimeout(() => this.alerts = this.alerts.filter(a => a !== alert), timeout);
        }
    }
};
</script>
