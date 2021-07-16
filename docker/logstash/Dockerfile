FROM docker.elastic.co/logstash/logstash:7.13.3
RUN rm -f /usr/share/logstash/pipeline/logstash.conf
RUN rm -f /usr/share/logstash/config/logstash.yml
# RUN logstash-plugin install logstash-input-beats
RUN logstash-plugin install logstash-output-amazon_es

COPY ./logstash.yml /usr/share/logstash/config/
CMD echo -en "$LOGSTASH_CONFIG" > /usr/share/logstash/pipeline/logstash.conf && /usr/share/logstash/bin/logstash
