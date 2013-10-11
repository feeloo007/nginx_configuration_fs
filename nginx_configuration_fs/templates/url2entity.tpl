{% import 'listening_uri_extra.tpl' as listening_uri_extra %}
map $scheme://$host:$server_port$request_uri $url_2_entity_{{ suffix_map }} {

    default     "__default__";

    {% for url2entity in url2entity_configurations -%}
    {{ listening_uri_extra.is_case_sensitive( url2entity.uri.extra ) }}^{{ url2entity.uri }}       {{url2entity.appcode}}-{{url2entity.env}}-{{url2entity.aera}}-NGV{{url2entity.virtual_ngv_num}};
    {% endfor -%}

}
