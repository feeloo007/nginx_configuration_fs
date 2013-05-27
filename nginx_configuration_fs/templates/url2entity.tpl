map $scheme://$host:$server_port$uri $url_2_entity_{{ suffix_map }} {

    default     "__default__";

    {% for url2entity in url2entity_configurations -%}
    ~^{{ url2entity.uri }}       {{url2entity.appcode}}-{{url2entity.env}}-{{url2entity.aera}}-NGV{{url2entity.virtual_ngv_num}};
    {% endfor -%}

}
