#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .exceptions import (
    AttributeFromPatternParsingError, UndefinedSTIXObjectError,
    UndefinedIndicatorError, UndefinedObservableError,
    UnknownObservableMappingError, UnknownParsingFunctionError,
    UnknownStixObjectTypeError)
from .importparser import _INDICATOR_TYPING
from .internal_stix2_mapping import InternalSTIX2toMISPMapping
from .converters import (
    InternalSTIX2AttackPatternConverter, InternalSTIX2MalwareAnalysisConverter,
    InternalSTIX2MalwareConverter)
from .stix2_to_misp import (
    STIX2toMISPParser, _COURSE_OF_ACTION_TYPING, _GALAXY_OBJECTS_TYPING,
    _IDENTITY_TYPING, _NETWORK_TRAFFIC_TYPING, _OBSERVABLE_TYPING,
    _OBSERVED_DATA_TYPING, _SDO_TYPING, _VULNERABILITY_TYPING)
from collections import defaultdict
from copy import deepcopy
from pymisp import MISPGalaxy, MISPGalaxyCluster, MISPObject, MISPSighting
from stix2.v20.common import ExternalReference as ExternalReference_v20
from stix2.v20.observables import (
    Process as Process_v20, WindowsPEBinaryExt as WindowsExtension_v20)
from stix2.v20.sdo import (
    CustomObject as CustomObject_v20, Malware as Malware_v20,
    ObservedData as ObservedData_v20, Tool as Tool_v20)
from stix2.v21.common import ExternalReference as ExternalReference_v21
from stix2.v21.observables import (
    DomainName, Process as Process_v21, WindowsPEBinaryExt as WindowsExtension_v21)
from stix2.v21.sdo import (
    CustomObject as CustomObject_v21, Indicator as Indicator_v21, Location,
    Malware as Malware_v21, ObservedData as ObservedData_v21, Tool as Tool_v21)
from typing import Optional, Union

_attribute_additional_fields = (
    'category',
    'comment',
    'data',
    'to_ids',
    'uuid'
)
_CUSTOM_TYPING = Union[
    CustomObject_v20,
    CustomObject_v21
]
_EXTENSION_TYPING = Union[
    WindowsExtension_v20,
    WindowsExtension_v21
]
_EXTERNAL_REFERENCE_TYPING = [
    ExternalReference_v20,
    ExternalReference_v21
]
_PROCESS_TYPING = Union[
    Process_v20,
    Process_v21
]
_SCRIPT_TYPING = Union[
    Malware_v20, Malware_v21,
    Tool_v20, Tool_v21
]


class InternalSTIX2toMISPParser(STIX2toMISPParser):
    def __init__(self, distribution: Optional[int] = 0,
                 sharing_group_id: Optional[int] = None,
                 galaxies_as_tags: Optional[bool] = False):
        super().__init__(distribution, sharing_group_id, galaxies_as_tags)
        self._mapping = InternalSTIX2toMISPMapping
        # parsers
        self._attack_pattern_parser: InternalSTIX2AttackPatternConverter
        self._malware_analysis_parser: InternalSTIX2MalwareAnalysisConverter
        self._malware_parser: InternalSTIX2MalwareConverter

    def _set_attack_pattern_parser(self) -> InternalSTIX2AttackPatternConverter:
        self._attack_pattern_parser = InternalSTIX2AttackPatternConverter(self)
        return self._attack_pattern_parser

    def _set_malware_analysis_parser(self) -> InternalSTIX2MalwareAnalysisConverter:
        self._malware_analysis_parser = InternalSTIX2MalwareAnalysisConverter(self)
        return self._malware_analysis_parser

    def _set_malware_parser(self) -> InternalSTIX2MalwareConverter:
        self._malware_parser = InternalSTIX2MalwareConverter(self)
        return self._malware_parser

    ################################################################################
    #                        STIX OBJECTS LOADING FUNCTIONS                        #
    ################################################################################

    def _load_custom_attribute(self, custom_attribute: _CUSTOM_TYPING):
        self._check_uuid(custom_attribute.id)
        try:
            self._custom_attribute[custom_attribute.id] = custom_attribute
        except AttributeError:
            self._custom_attribute = {custom_attribute.id: custom_attribute}

    def _load_custom_galaxy_cluster(self, custom_galaxy: _CUSTOM_TYPING):
        self._check_uuid(custom_galaxy.id)
        try:
            self._custom_galaxy_cluster[custom_galaxy.id] = custom_galaxy
        except AttributeError:
            self._custom_galaxy_cluster = {custom_galaxy.id: custom_galaxy}

    def _load_custom_object(self, custom_object: _CUSTOM_TYPING):
        self._check_uuid(custom_object.id)
        try:
            self._custom_object[custom_object.id] = custom_object
        except AttributeError:
            self._custom_object = {custom_object.id: custom_object}

    def _load_custom_opinion(self, custom_object: CustomObject_v20):
        sighting = MISPSighting()
        sighting_args = {
            'date_sighting': self._timestamp_from_date(custom_object.modified),
            'type': '1'
        }
        if hasattr(custom_object, 'x_misp_source'):
            sighting_args['source'] = custom_object.x_misp_source
        if hasattr(custom_object, 'x_misp_author'):
            sighting_args['Organisation'] = {
                'uuid': custom_object.x_misp_author_ref.split('--')[1],
                'name': custom_object.x_misp_author
            }
        sighting.from_dict(**sighting_args)
        object_ref = self._sanitise_uuid(custom_object.object_ref)
        try:
            self._sighting['custom_opinion'][object_ref].append(sighting)
        except AttributeError:
            self._sighting = defaultdict(lambda: defaultdict(list))
            self._sighting['custom_opinion'][object_ref].append(sighting)

    def _load_observable_object(self, observable: _OBSERVABLE_TYPING):
        self._check_uuid(observable.id)
        try:
            self._observable[observable.id] = observable
        except AttributeError:
            self._observable = {observable.id: observable}

    ################################################################################
    #                     MAIN STIX OBJECTS PARSING FUNCTIONS.                     #
    ################################################################################

    def _handle_indicator_object_mapping(
            self, labels: list, object_id: str) -> str:
        parsed_labels = {
            key: value.strip('"') for key, value
            in (label.split('=')for label in labels)
        }
        if 'misp:name' in parsed_labels:
            to_call = self._mapping.objects_mapping(parsed_labels['misp:name'])
            if to_call is not None:
                return to_call
        elif 'misp:type' in parsed_labels:
            to_call = self._mapping.indicator_attributes_mapping(
                parsed_labels['misp:type']
            )
            if to_call is not None:
                return to_call
        raise UndefinedIndicatorError(object_id)

    def _handle_object_mapping(self, labels: list, object_id: str) -> str:
        parsed_labels = {
            key: value.strip('"') for key, value
            in (label.split('=') for label in labels)
        }
        if 'misp:galaxy-type' in parsed_labels:
            return '_parse_galaxy'
        if 'misp:name' in parsed_labels:
            to_call = self._mapping.objects_mapping(parsed_labels['misp:name'])
            if to_call is not None:
                return to_call
        elif 'misp:type' in parsed_labels:
            to_call = self._mapping.attributes_mapping(
                parsed_labels['misp:type']
            )
            if to_call is not None:
                return to_call
        raise UndefinedSTIXObjectError(object_id)

    def _handle_object_refs(self, object_refs: list):
        for object_ref in object_refs:
            object_type = object_ref.split('--')[0]
            if object_type in self._mapping.object_type_refs_to_skip():
                continue
            try:
                self._handle_object(object_type, object_ref)
            except UnknownStixObjectTypeError as error:
                self._unknown_stix_object_type_error(error)
            except UnknownParsingFunctionError as error:
                self._unknown_parsing_function_error(error)

    def _handle_observable_object_mapping(
            self, labels: list, object_id: str) -> str:
        parsed_labels = {
            key: value.strip('"') for key, value
            in (label.split('=') for label in labels)
        }
        if 'misp:name' in parsed_labels:
            to_call = self._mapping.objects_mapping(parsed_labels['misp:name'])
            if to_call is not None:
                return to_call
        elif 'misp:type' in parsed_labels:
            to_call = self._mapping.observable_attributes_mapping(
                parsed_labels['misp:type']
            )
            if to_call is not None:
                return to_call
        raise UndefinedObservableError(object_id)

    def _parse_campaign(self, campaign_ref: str):
        campaign = self._get_stix_object(campaign_ref)
        attribute = self._create_attribute_dict(campaign)
        attribute['value'] = campaign.name
        self._add_misp_attribute(attribute, campaign)

    def _parse_course_of_action(self, course_of_action_ref: str):
        course_of_action = self._get_stix_object(course_of_action_ref)
        feature = self._handle_object_mapping(
            course_of_action.labels, course_of_action.id
        )
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(course_of_action)
        except Exception as exception:
            self._course_of_action_error(course_of_action.id, exception)

    def _parse_custom_attribute(self, custom_ref: str):
        custom_attribute = self._get_stix_object(custom_ref)
        attribute = {
            "type": custom_attribute.x_misp_type,
            "value": self._sanitise_value(custom_attribute.x_misp_value),
            "timestamp": self._timestamp_from_date(custom_attribute.modified)
        }
        for field in _attribute_additional_fields:
            if hasattr(custom_attribute, f'x_misp_{field}'):
                attribute[field] = getattr(custom_attribute, f'x_misp_{field}')
        attribute.update(
            self._sanitise_attribute_uuid(
                custom_attribute.id, comment=attribute.get('comment')
            )
        )
        self._add_misp_attribute(attribute, custom_attribute)

    def _parse_custom_galaxy_cluster(self, custom_ref: str):
        if custom_ref in self._clusters:
            self._clusters[custom_ref]['used'][self.misp_event.uuid] = False
        else:
            custom_galaxy = self._get_stix_object(custom_ref)
            galaxy_type = custom_galaxy.x_misp_type
            galaxy_description, cluster_description = custom_galaxy.x_misp_description.split(' | ')
            cluster_args = {
                'type': galaxy_type,
                'value': custom_galaxy.x_misp_value,
                'description': cluster_description
            }
            if hasattr(custom_galaxy, 'x_misp_meta'):
                cluster_args['meta'] = custom_galaxy.x_misp_meta
            self._clusters[custom_ref] = {
                'cluster': self._create_misp_galaxy_cluster(cluster_args),
                'used': {self.misp_event.uuid: False}
            }
            if galaxy_type not in self._galaxies:
                self._create_galaxy_args(
                    galaxy_description, galaxy_type, custom_galaxy.x_misp_name
                )

    def _parse_custom_object(self, custom_ref: str):
        custom_object = self._get_stix_object(custom_ref)
        name = custom_object.x_misp_name
        misp_object = self._create_misp_object(name)
        misp_object.category = custom_object.x_misp_meta_category
        misp_object.from_dict(**self._parse_timeline(custom_object))
        if hasattr(custom_object, 'x_misp_comment'):
            misp_object.comment = custom_object.x_misp_comment
        self._sanitise_object_uuid(misp_object, custom_object.id)
        for custom_attribute in custom_object.x_misp_attributes:
            attribute = dict(custom_attribute)
            if attribute.get('uuid'):
                attribute.update(
                    self._sanitise_attribute_uuid(
                        attribute['uuid'], attribute.get('comment')
                    )
                )
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, custom_object)

    def _parse_identity(self, identity_ref: str):
        if identity_ref not in self._creators:
            identity = self._get_stix_object(identity_ref)
            feature = self._handle_object_mapping(identity.labels, identity.id)
            try:
                parser = getattr(self, feature)
            except AttributeError:
                raise UnknownParsingFunctionError(feature)
            try:
                parser(identity)
            except Exception as exception:
                self._identity_error(identity.id, exception)

    def _parse_indicator(self, indicator_ref: str):
        indicator = self._get_stix_object(indicator_ref)
        feature = self._handle_indicator_object_mapping(
            indicator.labels, indicator.id
        )
        try:
            parser = getattr(self, f"{feature}_indicator")
        except AttributeError:
            raise UnknownParsingFunctionError(f"{feature}_indicator")
        try:
            parser(indicator)
        except AttributeFromPatternParsingError as error:
            self._attribute_from_pattern_parsing_error(error)
        except Exception as exception:
            self._indicator_error(indicator.id, exception)

    def _parse_intrusion_set(self, intrusion_set_ref: str):
        intrusion_set = self._get_stix_object(intrusion_set_ref)
        feature = self._handle_object_mapping(
            intrusion_set.labels, intrusion_set.id
        )
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(intrusion_set)
        except Exception as exception:
            self._intrusion_set_error(intrusion_set.id, exception)

    def _parse_location(self, location_ref: str):
        location = self._get_stix_object(location_ref)
        feature = self._handle_object_mapping(location.labels, location.id)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(location)
        except Exception as exception:
            self._location_error(location.id, exception)

    def _parse_note(self, note_ref: str):
        note = self._get_stix_object(note_ref)
        misp_object = self._create_misp_object('annotation', note)
        self._sanitise_object_uuid(misp_object, note.id)
        misp_object.from_dict(**self._parse_timeline(note))
        for feature, mapping in self._mapping.annotation_object_mapping().items():
            if hasattr(note, feature):
                self._populate_object_attributes_with_data(
                    misp_object,
                    mapping,
                    getattr(note, feature)
                )
        if hasattr(note, 'object_refs'):
            for object_ref in note.object_refs:
                misp_object.add_reference(
                    self._sanitise_uuid(object_ref), 'annotates'
                )
        self._add_misp_object(misp_object, note)

    def _parse_observed_data(self, observed_data_ref: str):
        observed_data = self._get_stix_object(observed_data_ref)
        feature = self._handle_observable_object_mapping(
            observed_data.labels, observed_data.id
        )
        version = getattr(observed_data, 'spec_version', '2.0')
        to_call = f"{feature}_observable_v{version.replace('.', '')}"
        try:
            parser = getattr(self, to_call)
        except AttributeError:
            raise UnknownParsingFunctionError(to_call)
        try:
            parser(observed_data)
        except UnknownObservableMappingError as observable_types:
            self._observable_mapping_error(observed_data.id, observable_types)

    def _parse_threat_actor(self, threat_actor_ref: str):
        threat_actor = self._get_stix_object(threat_actor_ref)
        feature = self._handle_object_mapping(
            threat_actor.labels, threat_actor.id
        )
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(threat_actor)
        except Exception as exception:
            self._threat_actor_error(threat_actor.id, exception)

    def _parse_tool(self, tool_ref: str):
        tool = self._get_stix_object(tool_ref)
        feature = self._handle_object_mapping(tool.labels, tool.id)
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(tool)
        except Exception as exception:
            self._tool_error(tool.id, exception)

    def _parse_vulnerability(self, vulnerability_ref: str):
        vulnerability = self._get_stix_object(vulnerability_ref)
        feature = self._handle_object_mapping(
            vulnerability.labels, vulnerability.id
        )
        try:
            parser = getattr(self, feature)
        except AttributeError:
            raise UnknownParsingFunctionError(feature)
        try:
            parser(vulnerability)
        except Exception as exception:
            self._vulnerability_error(vulnerability.id, exception)

    ################################################################################
    #                 STIX Domain Objects (SDOs) PARSING FUNCTIONS                 #
    ################################################################################

    def _create_galaxy_args(self, description: str, galaxy_type: str,
                            galaxy_name: str) -> MISPGalaxy:
        misp_galaxy = MISPGalaxy()
        misp_galaxy.from_dict(
            **{
                'type': galaxy_type,
                'name': galaxy_name,
                'description': description
            }
        )
        self._galaxies[galaxy_type] = misp_galaxy

    def _parse_course_of_action_object(
            self, course_of_action: _COURSE_OF_ACTION_TYPING):
        misp_object = self._create_misp_object(
            'course-of-action', course_of_action
        )
        for key, mapping in self._mapping.course_of_action_object_mapping().items():
            if hasattr(course_of_action, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(course_of_action, key)
                )
        self._add_misp_object(misp_object, course_of_action)

    def _parse_employee_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._create_misp_object('employee', identity)
        for key, mapping in self._mapping.employee_object_mapping().items():
            if hasattr(identity, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(identity, key)
                )
        if hasattr(identity, 'contact_information'):
            object_relation, value = identity.contact_information.split(': ')
            attribute = {
                'type': 'target-email',
                'object_relation': object_relation,
                'value': value
            }
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, identity)

    def _parse_galaxy(self, stix_object: _GALAXY_OBJECTS_TYPING):
        if stix_object.id in self._clusters:
            self._clusters[stix_object.id]['used'][self.misp_event.uuid] = False
        else:
            feature = f'_parse_galaxy_{self.galaxy_feature}'
            self._clusters[stix_object.id] = getattr(self, feature)(stix_object)

    def _parse_galaxy_as_container(
            self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        galaxy_type, galaxy_name = self._extract_galaxy_labels(
            stix_object.labels
        )
        cluster, galaxy_description = self._parse_galaxy_cluster(
            stix_object, galaxy_type
        )
        if galaxy_type not in self._galaxies:
            self._create_galaxy_args(
                galaxy_description, galaxy_type, galaxy_name
            )
        return {
            'cluster': cluster,
            'used': {self.misp_event.uuid: False}
        }

    def _parse_galaxy_as_tag_names(
            self, stix_object: _GALAXY_OBJECTS_TYPING) -> dict:
        galaxy_type = stix_object.labels[1].split('=')[1].strip('"')
        return {
            'tag_names': [
                f'misp-galaxy:{galaxy_type}="{stix_object.name}"'
            ],
            'used': {self.misp_event.uuid: False}
        }

    def _parse_galaxy_cluster(self, stix_object: _GALAXY_OBJECTS_TYPING,
                              galaxy_type: str) -> tuple:
        object_type = stix_object.type.replace('-', '_')
        if ' | ' in stix_object.description:
            galaxy_desc, cluster_desc = stix_object.description.split(' | ')
            cluster = getattr(self, f'_parse_{object_type}_cluster')(
                stix_object,
                description=cluster_desc,
                galaxy_type=galaxy_type
            )
            return cluster, galaxy_desc
        cluster = getattr(self, f'_parse_{object_type}_cluster')(
            stix_object, galaxy_type=galaxy_type
        )
        return cluster, stix_object.description

    def _parse_identity_cluster(
            self, identity: _IDENTITY_TYPING, description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        identity_args = self._create_cluster_args(
            identity, galaxy_type, description=description
        )
        return self._create_misp_galaxy_cluster(identity_args)

    def _parse_identity_object(
            self, identity: _IDENTITY_TYPING, name: str) -> MISPObject:
        misp_object = self._create_misp_object(name, identity)
        feature = name.replace('-', '_')
        for key, mapping in getattr(self._mapping, f'{feature}_object_mapping')().items():
            if hasattr(identity, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(identity, key)
                )
        if hasattr(identity, 'contact_information'):
            mapping = getattr(
                self._mapping, f'{feature}_contact_information_mapping'
            )
            contact_information = []
            for contact_info in identity.contact_information.split(' / '):
                if ': ' in contact_info:
                    try:
                        object_relation, value = contact_info.split(': ')
                    except ValueError:
                        contact_information.append(contact_info)
                        continue
                    attribute = mapping(object_relation)
                    if attribute is not None:
                        misp_object.add_attribute(
                            **{
                                'object_relation': object_relation,
                                'value': value, **attribute
                            }
                        )
                        continue
                contact_information.append(contact_info)
            if contact_information:
                misp_object.add_attribute(
                    'contact_information', '; '.join(contact_information)
                )
        return misp_object

    def _parse_legal_entity_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._parse_identity_object(identity, 'legal-entity')
        if hasattr(identity, 'x_misp_logo'):
            attribute = {'type': 'attachment', 'object_relation': 'logo'}
            if isinstance(identity.x_misp_logo, dict):
                attribute.update(identity.x_misp_logo)
            else:
                attribute['value'] = identity.x_misp_logo
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, identity)

    def _parse_location_cluster(
            self, location: Location, description: Optional[str] = None,
            galaxy_type: Optional[str] = None) -> MISPGalaxyCluster:
        location_args = {
            'type': galaxy_type,
            'description': description,
            'value': location.name if galaxy_type == 'country'
            else self._mapping.regions_mapping(location.region, location.name)
        }
        meta = self._handle_meta_fields(location)
        if meta:
            location_args['meta'] = meta
        return self._create_misp_galaxy_cluster(location_args)

    def _parse_news_agency_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._parse_identity_object(identity, 'news-agency')
        if hasattr(identity, 'x_misp_attachment'):
            attribute = {'type': 'attachment', 'object_relation': 'attachment'}
            if isinstance(identity.x_misp_attachment, dict):
                attribute.update(identity.x_misp_attachment)
            else:
                attribute['value'] = identity.x_misp_attachment
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, identity)

    def _parse_organization_object(self, identity: _IDENTITY_TYPING):
        misp_object = self._parse_identity_object(identity, 'organization')
        self._add_misp_object(misp_object, identity)

    def _parse_script_object(self, stix_object: _SCRIPT_TYPING):
        misp_object = self._create_misp_object('script', stix_object)
        feature = f'script_from_{stix_object.type}_object_mapping'
        for key, mapping in getattr(self._mapping, feature)().items():
            if hasattr(stix_object, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(stix_object, key)
                )
        if hasattr(stix_object, 'x_misp_script_as_attachment'):
            attribute = {
                'type': 'attachment',
                'object_relation': 'script-as-attachment'
            }
            if isinstance(stix_object.x_misp_script_as_attachment, dict):
                attribute.update(stix_object.x_misp_script_as_attachment)
            else:
                attribute['value'] = stix_object.x_misp_script_as_attachment
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, stix_object)

    def _parse_vulnerability_attribute(
            self, vulnerability: _VULNERABILITY_TYPING):
        attribute = self._create_attribute_dict(vulnerability)
        attribute['value'] = vulnerability.name
        self._add_misp_attribute(attribute, vulnerability)

    def _parse_vulnerability_object(self, vulnerability: _VULNERABILITY_TYPING):
        misp_object = self._create_misp_object('vulnerability', vulnerability)
        for reference in vulnerability.external_references:
            if reference['source_name'] in ('cve', 'vulnerability'):
                external_id = reference['external_id']
                misp_object.add_attribute(
                    **{
                        'value': external_id,
                        **self._mapping.vulnerability_attribute()
                    }
                )
                if external_id != vulnerability.name:
                    misp_object.add_attribute(
                        **{
                            'value': vulnerability.name,
                            **self._mapping.summary_attribute()
                        }
                    )
            elif reference['source_name'] == 'url':
                misp_object.add_attribute(
                    **{
                        'value': reference['url'],
                        **self._mapping.references_attribute()
                    }
                )
        for key, mapping in self._mapping.vulnerability_object_mapping().items():
            if hasattr(vulnerability, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(vulnerability, key)
                )
        self._add_misp_object(misp_object, vulnerability)

    ################################################################################
    #                     OBSERVABLE OBJECTS PARSING FUNCTIONS                     #
    ################################################################################

    def _attribute_from_address_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        for observable_object in observed_data.objects.values():
            if '-addr' in observable_object.type:
                attribute['value'] = observable_object.value
                break
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_address_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        for reference in observed_data.object_refs:
            if '-addr' in reference:
                observable = self._fetch_observables(reference)
                attribute['value'] = observable.value
                break
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_AS_observable_v20(self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        attribute['value'] = self._parse_AS_value(observable.number)
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_AS_observable_v21(self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = self._parse_AS_value(observable.number)
        self._add_misp_attribute(attribute, observed_data)

    @staticmethod
    def _attribute_from_attachment_observable(observables: tuple) -> dict:
        attribute = {}
        for observable in observables:
            if observable.type == 'file':
                attribute['value'] = observable.name
            else:
                attribute['data'] = observable.payload_bin
        return attribute

    def _attribute_from_attachment_observable_v20(
            self, observed_data: ObservedData_v20):
        self._add_misp_attribute(
            dict(
                self._create_attribute_dict(observed_data),
                **self._attribute_from_attachment_observable(
                    tuple(observed_data.objects.values())
                )
            ),
            observed_data
        )

    def _attribute_from_attachment_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observables = self._fetch_observables(observed_data.object_refs)
        if isinstance(observables, tuple):
            attribute.update(
                self._attribute_from_attachment_observable(observables)
            )
        else:
            attribute['value'] = observables.name
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_domain_ip_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        domain, address = observed_data.objects.values()
        attribute['value'] = f'{domain.value}|{address.value}'
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_domain_ip_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        domain, address = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = f'{domain.value}|{address.value}'
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_attachment_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['1'].name
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_attachment_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs[1])
        attribute['value'] = observable.name
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_body_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].body
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_body_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.body
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_header_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].received_lines[0]
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_header_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.received_lines[0]
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_message_id_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.message_id
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_reply_to_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        email_message = observed_data.objects['0']
        attribute['value'] = email_message.additional_header_fields['Reply-To']
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_reply_to_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.additional_header_fields['Reply-To']
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_subject_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].subject
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_subject_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.subject
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_x_mailer_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        email_message = observed_data.objects['0']
        attribute['value'] = email_message.additional_header_fields['X-Mailer']
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_email_x_mailer_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.additional_header_fields['X-Mailer']
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_filename_hash_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        hash_value = list(observable.hashes.values())[0]
        attribute['value'] = f'{observable.name}|{hash_value}'
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_filename_hash_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        hash_value = list(observable.hashes.values())[0]
        attribute['value'] = f'{observable.name}|{hash_value}'
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_first_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].value
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_first_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs[0])
        attribute['value'] = observable.value
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_github_username_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.account_login
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hash_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = list(observed_data.objects['0'].hashes.values())[0]
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hash_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = list(observable.hashes.values())[0]
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hostname_port_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        domain, network = observed_data.objects.values()
        attribute['value'] = f'{domain.value}|{network.dst_port}'
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_hostname_port_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        domain, network = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = f'{domain.value}|{network.dst_port}'
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_ip_port_observable(
            self, network_traffic :_NETWORK_TRAFFIC_TYPING,
            ip_value: str, observed_data: _OBSERVED_DATA_TYPING):
        attribute = self._create_attribute_dict(observed_data)
        for feature in ('src_port', 'dst_port'):
            if hasattr(network_traffic, feature):
                port_value = getattr(network_traffic, feature)
                attribute['value'] = f'{ip_value}|{port_value}'
                self._add_misp_attribute(attribute, observed_data)
                break

    def _attribute_from_ip_port_observable_v20(
            self, observed_data: ObservedData_v20):
        self._attribute_from_ip_port_observable(
            observed_data.objects['0'], observed_data.objects['1'].value,
            observed_data
        )

    def _attribute_from_ip_port_observable_v21(
            self, observed_data: ObservedData_v21):
        network, address = self._fetch_observables(
            observed_data.object_refs
        )
        self._attribute_from_ip_port_observable(
            network, address.value, observed_data
        )

    @staticmethod
    def _attribute_from_malware_sample_observable(observables: tuple) -> dict:
        attribute = {}
        for observable in observables:
            if observable.type == 'file':
                attribute['value'] = f"{observable.name}|{observable.hashes['MD5']}"
            else:
                attribute['data'] = observable.payload_bin
        return attribute

    def _attribute_from_malware_sample_observable_v20(
            self, observed_data: ObservedData_v20):
        self._add_misp_attribute(
            dict(
                self._create_attribute_dict(observed_data),
                **self._attribute_from_malware_sample_observable(
                    observed_data.objects.values()
                )
            ),
            observed_data
        )

    def _attribute_from_malware_sample_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observables = self._fetch_observables(observed_data.object_refs)
        if isinstance(observables, tuple):
            attribute.update(
                self._attribute_from_malware_sample_observable(observables)
            )
        else:
            attribute['value'] = f"{observables.name}|{observables.hashes['MD5']}"
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_name_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].name
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_name_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.name
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        attribute['value'] = observed_data.objects['0'].key
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = observable.key
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_value_observable_v20(
            self, observed_data: ObservedData_v20):
        attribute = self._create_attribute_dict(observed_data)
        observable = observed_data.objects['0']
        attribute['value'] = f"{observable.key}|{observable['values'][0].data}"
        self._add_misp_attribute(attribute, observed_data)

    def _attribute_from_regkey_value_observable_v21(
            self, observed_data: ObservedData_v21):
        attribute = self._create_attribute_dict(observed_data)
        observable = self._fetch_observables(observed_data.object_refs)
        attribute['value'] = f"{observable.key}|{observable['values'][0].data}"
        self._add_misp_attribute(attribute, observed_data)

    def _object_from_account_with_attachment_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, name: str, version: str):
        misp_object = self._create_misp_object(name, observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        feature = f"{name.replace('-', '_')}_object_mapping"
        for feature, mapping in getattr(self._mapping, feature)().items():
            if hasattr(observable, feature):
                if feature.startswith('x_misp_'):
                    self._populate_object_attributes_with_data(
                        misp_object,
                        mapping,
                        getattr(observable, feature)
                    )
                else:
                    self._populate_object_attributes(
                        misp_object,
                        mapping,
                        getattr(observable, feature)
                    )
        self._add_misp_object(misp_object, observed_data)

    def _object_from_android_app_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_standard_observable(observed_data, 'android-app', 'v20')

    def _object_from_android_app_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_standard_observable(observed_data, 'android-app', 'v21')

    def _object_from_asn_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('asn', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        for feature, mapping in self._mapping.asn_object_mapping().items():
            if hasattr(observable, feature):
                value = getattr(observable, feature)
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    self._parse_AS_value(value) if feature == 'number' else value
                )
        self._add_misp_object(misp_object, observed_data)

    def _object_from_asn_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_asn_observable(observed_data, 'v20')

    def _object_from_asn_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_asn_observable(observed_data, 'v21')

    def _object_from_cpe_asset_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_standard_observable(observed_data, 'cpe-asset', 'v20')

    def _object_from_cpe_asset_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_standard_observable(observed_data, 'cpe-asset', 'v21')

    def _object_from_credential_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_standard_observable(observed_data, 'credential', 'v20')

    def _object_from_credential_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_standard_observable(observed_data, 'credential', 'v21')

    def _object_from_domain_ip_observable_v20(
            self, observed_data: ObservedData_v20):
        misp_object = self._create_misp_object('domain-ip', observed_data)
        parsed = []
        for observable in observed_data.objects.values():
            if observable.type == 'domain-name':
                for feature, mapping in self._mapping.domain_ip_object_mapping().items():
                    if hasattr(observable, feature):
                        misp_object.add_attribute(
                            **{
                                'value': getattr(observable, feature),
                                **mapping
                            }
                        )
                if hasattr(observable, 'resolves_to_refs'):
                    for reference in observable.resolves_to_refs:
                        if reference in parsed:
                            continue
                        misp_object.add_attribute(
                            **{
                                'value': observed_data.objects[reference].value,
                                **self._mapping.ip_attribute()
                            }
                        )
                        parsed.append(reference)
        self._add_misp_object(misp_object, observed_data)

    def _object_from_domain_ip_observable_v21(
            self, observed_data: ObservedData_v21):
        misp_object = self._create_misp_object('domain-ip', observed_data)
        parsed = []
        for object_ref in observed_data.object_refs:
            if object_ref.startswith('domain-name--'):
                observable = self._observable[object_ref]
                if self._has_domain_custom_fields(observable):
                    for feature, mapping in self._mapping.domain_ip_object_mapping().items():
                        if hasattr(observable, feature):
                            attribute = {
                                'value': getattr(observable, feature),
                                **mapping
                            }
                            misp_object.add_attribute(**attribute)
                else:
                    misp_object.add_attribute(
                        **{
                            'type': 'domain',
                            'object_relation': 'domain',
                            'value': observable.value,
                            **self._sanitise_attribute_uuid(observable.id)
                        }
                    )
                if hasattr(observable, 'resolves_to_refs'):
                    for reference in observable.resolves_to_refs:
                        if reference in parsed:
                            continue
                        address = self._observable[reference]
                        misp_object.add_attribute(
                            **{
                                'value': address.value,
                                **self._mapping.ip_attribute(),
                                **self._sanitise_attribute_uuid(address.id)
                            }
                        )
                        parsed.append(reference)
        self._add_misp_object(misp_object, observed_data)

    def _object_from_email_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('email', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        to_call = f'_create_attribute_from_reference_{version}'
        for observable in observables.values():
            if observable.type != 'email-message':
                continue
            if hasattr(observable, 'from_ref'):
                reference = observables[observable.from_ref]
                attribute = getattr(self, to_call)(
                    'email-src',
                    'from',
                    'value',
                    reference
                )
                misp_object.add_attribute(**attribute)
                if hasattr(reference, 'display_name'):
                    misp_object.add_attribute(
                        **{
                            'type': 'email-src-display-name',
                            'object_relation': 'from-display-name',
                            'value': reference.display_name
                        }
                    )
            for feature in ('to', 'cc', 'bcc'):
                if hasattr(observable, f'{feature}_refs'):
                    for ref in getattr(observable, f'{feature}_refs'):
                        reference = observables[ref]
                        attribute = getattr(self, to_call)(
                            'email-dst',
                            feature,
                            'value',
                            reference
                        )
                        misp_object.add_attribute(**attribute)
                        if hasattr(reference, 'display_name'):
                            misp_object.add_attribute(
                                **{
                                    'type': 'email-dst-display-name',
                                    'object_relation': f'{feature}-display-name',
                                    'value': reference.display_name
                                }
                            )
            for feature, mapping in self._mapping.email_object_mapping().items():
                if hasattr(observable, feature):
                    self._populate_object_attributes(
                        misp_object,
                        mapping,
                        getattr(observable, feature)
                    )
            if hasattr(observable, 'additional_header_fields'):
                header = observable.additional_header_fields
                for feature, mapping in self._mapping.email_additional_header_fields_mapping().items():
                    if feature in header:
                        self._populate_object_attributes(
                            misp_object,
                            mapping,
                            header[feature]
                        )
            if hasattr(observable, 'body_multipart'):
                for body_part in observable.body_multipart:
                    relation, value = body_part.content_disposition.split(';')
                    attribute_type = 'email-attachment' if relation == 'attachment' else 'attachment'
                    reference = observables[body_part.body_raw_ref]
                    if reference.type == 'file':
                        attribute = getattr(self, to_call)(
                            attribute_type,
                            relation,
                            'name',
                            reference
                        )
                        misp_object.add_attribute(**attribute)
                        continue
                    attribute = getattr(self, to_call)(
                        attribute_type,
                        relation,
                        'payload_bin',
                        reference
                    )
                    attribute['data'] = attribute.pop('value')
                    attribute['value'] = value.split('=').strip("'")
                    misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, observed_data)

    def _object_from_email_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_email_observable(observed_data, 'v20')

    def _object_from_email_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_email_observable(observed_data, 'v21')

    def _object_from_facebook_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'facebook-account', 'v20'
        )

    def _object_from_facebook_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'facebook-account', 'v21'
        )

    def _object_from_file_extension_observable(
            self, extension: _EXTENSION_TYPING,
            observed_data: _OBSERVED_DATA_TYPING) -> str:
        pe_object = self._create_misp_object('pe')
        pe_object.from_dict(**self._parse_timeline(observed_data))
        if hasattr(extension, 'optional_header'):
            pe_object.add_attribute(
                **{
                    'value': extension.optional_header.address_of_entry_point,
                    **self._mapping.entrypoint_address_attribute()
                }
            )
        for feature, mapping in self._mapping.pe_object_mapping().items():
            if hasattr(extension, feature):
                pe_object.add_attribute(
                    **{
                        'value': getattr(extension, feature),
                        **mapping
                    }
                )
        misp_object = self._add_misp_object(pe_object, observed_data)
        if hasattr(extension, 'sections'):
            for section in extension.sections:
                section_object = self._create_misp_object('pe-section')
                section_object.from_dict(**self._parse_timeline(observed_data))
                for feature, mapping in self._mapping.pe_section_object_mapping().items():
                    if hasattr(section, feature):
                        section_object.add_attribute(
                            **{
                                'value': getattr(section, feature),
                                **mapping
                            }
                        )
                if hasattr(section, 'hashes'):
                    for hash_type, hash_value in section.hashes.items():
                        section_object.add_attribute(
                            **{
                                'value': hash_value,
                                **self._mapping.file_hashes_mapping(hash_type)
                            }
                        )
                self._add_misp_object(section_object, observed_data)
                misp_object.add_reference(section_object.uuid, 'includes')
        return misp_object.uuid

    def _object_from_file_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        file_object = self._create_misp_object('file', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type != 'file':
                continue
            if hasattr(observable, 'hashes'):
                for hash_type, value in observable.hashes.items():
                    file_object.add_attribute(
                        **{
                            'value': value,
                            **self._mapping.file_hashes_mapping(hash_type)
                        }
                    )
            for feature, mapping in self._mapping.file_object_mapping().items():
                if hasattr(observable, feature):
                    self._populate_object_attributes_with_data(
                        file_object,
                        mapping,
                        getattr(observable, feature)
                    )
            if hasattr(observable, 'parent_directory_ref'):
                directory = observables[observable.parent_directory_ref]
                attribute = {
                    'type': 'text',
                    'object_relation': 'path',
                    'value': directory.path
                }
                if hasattr(directory, 'id'):
                    attribute.update(
                        self._sanitise_attribute_uuid(directory.id)
                    )
                file_object.add_attribute(**attribute)
            if hasattr(observable, 'content_ref'):
                artifact = observables[observable.content_ref]
                attribute = {
                    'value': artifact.x_misp_filename,
                    'data': artifact.payload_bin
                }
                if getattr(artifact, 'hashes', {}).get('MD5') is not None:
                    attribute.update(
                        {
                            'type': 'malware-sample',
                            'object_relation': 'malware-sample',
                            'value': f"{attribute['value']}|{artifact.hashes['MD5']}"
                        }
                    )
                else:
                    attribute.update(
                        {
                            'type': 'attachment',
                            'object_relation': 'attachment'
                        }
                    )
                if hasattr(artifact, 'id'):
                    attribute.update(
                        self._sanitise_attribute_uuid(artifact.id)
                    )
                file_object.add_attribute(**attribute)
            misp_object = self._add_misp_object(file_object, observed_data)
            if getattr(observable, 'extensions', {}).get('windows-pebinary-ext'):
                pe_uuid = self._object_from_file_extension_observable(
                    observable.extensions['windows-pebinary-ext'], observed_data
                )
                misp_object.add_reference(pe_uuid, 'includes')

    def _object_from_file_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_file_observable(observed_data, 'v20')

    def _object_from_file_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_file_observable(observed_data, 'v21')

    def _object_from_github_user_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'github-user', 'v20'
        )

    def _object_from_github_user_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'github-user', 'v21'
        )

    def _object_from_gitlab_user_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_standard_observable(
            observed_data, 'gitlab-user', 'v20'
        )

    def _object_from_gitlab_user_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_standard_observable(
            observed_data, 'gitlab-user', 'v21'
        )

    def _object_from_http_request_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('http-request', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type == 'network-traffic':
                for feature in ('src', 'dst'):
                    if hasattr(observable, f'{feature}_ref'):
                        address = observables[
                            getattr(observable, f'{feature}_ref')
                        ]
                        attribute = {
                            'value': address.value,
                            **getattr(self._mapping, f'ip_{feature}_attribute')()
                        }
                        if hasattr(address, 'id'):
                            attribute.update(
                                self._sanitise_attribute_uuid(address.id)
                            )
                        misp_object.add_attribute(**attribute)
                for feature, mapping in self._mapping.http_request_object_mapping().items():
                    if hasattr(observable, feature):
                        self._populate_object_attributes(
                            misp_object,
                            mapping,
                            getattr(observable, feature)
                        )
                if getattr(observable, 'extensions', {}).get('http-request-ext'):
                    extension = observable.extensions['http-request-ext']
                    for feature, mapping in self._mapping.http_request_extension_mapping().items():
                        if hasattr(extension, feature):
                            self._populate_object_attributes(
                                misp_object,
                                mapping,
                                getattr(extension, feature)
                            )
                    if hasattr(extension, 'request_header'):
                        for feature, mapping in self._mapping.http_request_header_mapping().items():
                            if extension.request_header.get(feature):
                                self._populate_object_attributes(
                                    misp_object,
                                    mapping,
                                    extension.request_header[feature]
                                )
            elif observable.type == 'domain-name':
                attribute = {
                    'value': observable.value,
                    **self._mapping.host_attribute()
                }
                if hasattr(observable, 'id'):
                    attribute.update(
                        self._sanitise_attribute_uuid(observable.id)
                    )
                misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, observed_data)

    def _object_from_http_request_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_http_request_observable(observed_data, 'v20')

    def _object_from_http_request_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_http_request_observable(observed_data, 'v21')

    def _object_from_image_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('image', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type == 'file':
                for feature, mapping in self._mapping.image_object_mapping().items():
                    if hasattr(observable, feature):
                        self._populate_object_attributes(
                            misp_object,
                            mapping,
                            getattr(observable, feature)
                        )
            elif observable.type == 'artifact':
                if hasattr(observable, 'payload_bin'):
                    attribute = {
                        'type': 'attachment',
                        'object_relation': 'attachment',
                        'value': observable.x_misp_filename,
                        'data': observable.payload_bin
                    }
                    if hasattr(observable, 'id'):
                        attribute.update(
                            self._sanitise_attribute_uuid(observable.id)
                        )
                    misp_object.add_attribute(**attribute)
                    if hasattr(observable, 'x_misp_url'):
                        misp_object.add_attribute(
                            **{
                                'value': observable.x_misp_url,
                                **self._mapping.url_attribute()
                            }
                        )
                elif hasattr(observable, 'url'):
                    attribute = {
                        'value': observable.url,
                        **self._mapping.url_attribute()
                    }
                    if hasattr(observable, 'id'):
                        attribute.update(
                            self._sanitise_attribute_uuid(observable.id)
                        )
                    misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, observed_data)

    def _object_from_image_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_image_observable(observed_data, 'v20')

    def _object_from_image_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_image_observable(observed_data, 'v21')

    def _object_from_ip_port_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('ip-port', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        ip_protocols: set = set()
        for observable in observables.values():
            if observable.type == 'network-traffic':
                for feature in ('src', 'dst'):
                    if hasattr(observable, f'{feature}_ref'):
                        address = observables[
                            getattr(observable, f'{feature}_ref')
                        ]
                        attribute = {
                            'value': address.value,
                            **getattr(self._mapping, f'ip_{feature}_attribute')()
                        }
                        if hasattr(address, 'id'):
                            attribute.update(
                                self._sanitise_attribute_uuid(address.id)
                            )
                        misp_object.add_attribute(**attribute)
                        ip_protocols.add(address.type.split('-')[0])
                for feature, mapping in self._mapping.ip_port_object_mapping().items():
                    if hasattr(observable, feature):
                        self._populate_object_attributes(
                            misp_object,
                            mapping,
                            getattr(observable, feature)
                        )
                for protocol in observable.protocols:
                    if protocol not in ip_protocols:
                        misp_object.add_attribute(
                            **{
                                'value': protocol,
                                **self._mapping.protocol_attribute()
                            }
                        )
                self._add_misp_object(misp_object, observed_data)

    def _object_from_ip_port_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_ip_port_observable(observed_data, 'v20')

    def _object_from_ip_port_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_ip_port_observable(observed_data, 'v21')

    def _object_from_lnk_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('lnk', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type != 'file':
                continue
            if hasattr(observable, 'hashes'):
                for hash_type, value in observable.hashes.items():
                    misp_object.add_attribute(
                        **{
                            'value': value,
                            **self._mapping.file_hashes_mapping(hash_type)
                        }
                    )
            for feature, mapping in self._mapping.lnk_object_mapping().items():
                if hasattr(observable, feature):
                    self._populate_object_attributes_with_data(
                        misp_object,
                        mapping,
                        getattr(observable, feature)
                    )
            if hasattr(observable, 'parent_directory_ref'):
                directory = observables[observable.parent_directory_ref]
                relation = 'fullpath' if hasattr(observable, 'name') and observable.name in directory.path else 'path'
                attribute = {
                    'type': 'text',
                    'object_relation': relation,
                    'value': directory.path
                }
                if hasattr(directory, 'id'):
                    attribute.update(
                        self._sanitise_attribute_uuid(directory.id)
                    )
                misp_object.add_attribute(**attribute)
            if hasattr(observable, 'content_ref'):
                artifact = observables[observable.content_ref]
                attribute = {
                    'type': 'malware-sample',
                    'object_relation': 'malware-sample',
                    'value': f"{artifact.x_misp_filename}|{artifact.hashes['MD5']}",
                    'data': artifact.payload_bin
                }
                if hasattr(artifact, 'id'):
                    attribute.update(
                        self._sanitise_attribute_uuid(artifact.id)
                    )
                misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, observed_data)

    def _object_from_lnk_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_lnk_observable(observed_data, 'v20')

    def _object_from_lnk_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_lnk_observable(observed_data, 'v21')

    def _object_from_mutex_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_standard_observable(observed_data, 'mutex', 'v20')

    def _object_from_mutex_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_standard_observable(observed_data, 'mutex', 'v21')

    def _object_from_netflow_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('netflow', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable in observables.values():
            if observable.type != 'network-traffic':
                continue
            for feature in ('src', 'dst'):
                if hasattr(observable, f'{feature}_ref'):
                    address = observables[getattr(observable, f'{feature}_ref')]
                    attribute = {
                        'value': address.value,
                        **getattr(self._mapping, f'ip_{feature}_attribute')()
                    }
                    if hasattr(address, 'id'):
                        attribute.update(
                            self._sanitise_attribute_uuid(address.id)
                        )
                    misp_object.add_attribute(**attribute)
                    if hasattr(address, 'belongs_to_refs'):
                        for as_reference in getattr(address, 'belongs_to_refs'):
                            autonomous_system = observables[as_reference]
                            attribute = {
                                'value': f'AS{autonomous_system.number}',
                                **getattr(self._mapping, f'{feature}_as_attribute')()
                            }
                            if hasattr(autonomous_system, 'id'):
                                attribute.update(
                                    self._sanitise_attribute_uuid(
                                        autonomous_system.id
                                    )
                                )
                            misp_object.add_attribute(**attribute)
            for feature, mapping in self._mapping.netflow_object_mapping().items():
                if hasattr(observable, feature):
                    self._populate_object_attributes(
                        misp_object,
                        mapping,
                        getattr(observable, feature)
                    )
            protocols = {protocol: False for protocol in observable.protocols}
            if hasattr(observable, 'extensions'):
                if observable.extensions.get('tcp-ext'):
                    misp_object.add_attribute(
                        **{
                            'value': getattr(
                                observable.extensions['tcp-ext'],
                                'src_flags_hex'
                            ),
                            **self._mapping.tcp_flags_attribute()
                        }
                    )
                    if 'tcp' in protocols:
                        protocols['tcp'] = True
                if observable.extensions.get('icmp-ext'):
                    misp_object.add_attribute(
                        **{
                            'value': getattr(
                                observable.extensions['icmp-ext'],
                                'icmp_type_hex'
                            ),
                            **self._mapping.icmp_type_attribute()
                        }
                    )
                    if 'icmp' in protocols:
                        protocols['icmp'] = True
            for protocol, present in protocols.items():
                if not present:
                    misp_object.add_attribute(
                        **{
                            'value': protocol.upper(),
                            **self._mapping.protocol_attribute()
                        }
                    )
                    break
            else:
                if len(protocols) == 1:
                    misp_object.add_attribute(
                        **{
                            'value': list(protocols.keys())[0].upper(),
                            **self._mapping.protocol_attribute()
                        }
                    )
            self._add_misp_object(misp_object, observed_data)

    def _object_from_netflow_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_netflow_observable(observed_data, 'v20')

    def _object_from_netflow_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_netflow_observable(observed_data, 'v21')

    def _object_from_network_connection_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable_id, observable in observables.items():
            if observable.type != 'network-traffic':
                continue
            misp_object = self._object_from_network_traffic_observable(
                'network-connection',
                observed_data,
                observables,
                observable_id
            )
            for prot in observable.protocols:
                protocol = prot.upper()
                layer = self._mapping.connection_protocols(protocol)
                misp_object.add_attribute(
                    **{
                        'type': 'text',
                        'object_relation': f'layer{layer}-protocol',
                        'value': protocol
                    }
                )
            self._add_misp_object(misp_object, observed_data)

    def _object_from_network_connection_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_network_connection_observable(observed_data, 'v20')

    def _object_from_network_connection_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_network_connection_observable(observed_data, 'v21')

    def _object_from_network_socket_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        for observable_id, observable in observables.items():
            if observable.type != 'network-traffic':
                continue
            misp_object = self._object_from_network_traffic_observable(
                'network-socket',
                observed_data,
                observables,
                observable_id
            )
            for prot in observable.protocols:
                protocol = prot.upper()
                misp_object.add_attribute(
                    **{
                        'type': 'text',
                        'object_relation': 'protocol',
                        'value': protocol
                    }
                )
            if getattr(observable, 'extensions', {}).get('socket-ext'):
                socket_ext = observable.extensions['socket-ext']
                for feature, mapping in self._mapping.network_socket_extension_object_mapping().items():
                    if hasattr(socket_ext, feature):
                        misp_object.add_attribute(
                            **{
                                'value': getattr(socket_ext, feature),
                                **mapping
                            }
                        )
                if getattr(socket_ext, 'is_listening', None) is not None:
                    misp_object.add_attribute(
                        **{
                            'type': 'text',
                            'object_relation': 'state',
                            'value': 'listening'
                        }
                    )
                elif getattr(socket_ext, 'is_blocking', None) is not None:
                    misp_object.add_attribute(
                        **{
                            'type': 'text',
                            'object_relation': 'state',
                            'value': 'blocking'
                        }
                    )
            self._add_misp_object(misp_object, observed_data)

    def _object_from_network_socket_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_network_socket_observable(observed_data, 'v20')

    def _object_from_network_socket_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_network_socket_observable(observed_data, 'v21')

    def _object_from_network_traffic_observable(
            self, name: str, observed_data: _OBSERVED_DATA_TYPING,
            observables: dict, observable_id: str) -> MISPObject:
        misp_object = self._create_misp_object(name, observed_data)
        observable = observables[observable_id]
        for feature in ('src', 'dst'):
            if hasattr(observable, f'{feature}_ref'):
                reference = observables[getattr(observable, f'{feature}_ref')]
                attribute = {'value': reference.value}
                if hasattr(reference, 'id'):
                    attribute.update(
                        self._sanitise_attribute_uuid(reference.id)
                    )
                if reference.type == 'domain-name':
                    attribute.update(
                        getattr(self._mapping, f'hostname_{feature}_attribute')()
                    )
                    misp_object.add_attribute(**attribute)
                    continue
                attribute.update(
                    getattr(self._mapping, f'ip_{feature}_attribute')()
                )
                misp_object.add_attribute(**attribute)
        mapping_name = f"{name.replace('-', '_')}_object_mapping"
        for feature, mapping in getattr(self._mapping, mapping_name)().items():
            if hasattr(observable, feature):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(observable, feature)
                )
        return misp_object

    def _object_from_parler_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'parler-account', 'v20'
        )

    def _object_from_parler_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'parler-account', 'v21'
        )

    def _object_from_process_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('process', observed_data)
        observables = getattr(self, f'_fetch_observables_with_id_{version}')(
            observed_data
        )
        main_process = self._fetch_main_process(observables)
        for feature, mapping in self._mapping.process_object_mapping().items():
            if hasattr(main_process, feature):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(main_process, feature)
                )
        if hasattr(main_process, 'binary_ref'):
            image = observables[main_process.binary_ref]
            misp_object.add_attribute(
                **{
                    'type': 'filename',
                    'object_relation': 'image',
                    'value': image.name
                }
            )
        elif hasattr(main_process, 'image_ref'):
            image = observables[main_process.image_ref]
            misp_object.add_attribute(
                **{
                    'type': 'filename',
                    'object_relation': 'image',
                    'value': image.name,
                    **self._sanitise_attribute_uuid(image.id)
                }
            )
        if hasattr(main_process, 'child_refs'):
            for child_ref in main_process.child_refs:
                process = observables[child_ref]
                attribute = {
                    'type': 'text',
                    'object_relation': 'child-pid',
                    'value': process.pid
                }
                if hasattr(process, 'id'):
                    attribute.update(
                        self._sanitise_attribute_uuid(process.id)
                    )
                misp_object.add_attribute(**attribute)
        if hasattr(main_process, 'parent_ref'):
            parent_process = observables[main_process.parent_ref]
            for feature, mapping in self._mapping.parent_process_object_mapping().items():
                if hasattr(parent_process, feature):
                    attribute = {
                        'value': getattr(parent_process, feature), **mapping
                    }
                    if feature == 'pid' and hasattr(parent_process, 'id'):
                        attribute.update(
                            self._sanitise_attribute_uuid(parent_process.id)
                        )
                    misp_object.add_attribute(**attribute)
            if hasattr(parent_process, 'binary_ref'):
                image = observables[parent_process.binary_ref]
                misp_object.add_attribute(
                    **{
                        'type': 'filename',
                        'object_relation': 'parent-image',
                        'value': image.name
                    }
                )
            elif hasattr(parent_process, 'image_ref'):
                image = observables[parent_process.image_ref]
                misp_object.add_attribute(
                    **{
                        'type': 'filename',
                        'object_relation': 'parent-image',
                        'value': image.name,
                        **self._sanitise_attribute_uuid(image.id)
                    }
                )
        self._add_misp_object(misp_object, observed_data)

    def _object_from_process_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_process_observable(observed_data, 'v20')

    def _object_from_process_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_process_observable(observed_data, 'v21')

    def _object_from_reddit_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'reddit-account', 'v20'
        )

    def _object_from_reddit_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'reddit-account', 'v21'
        )

    def _object_from_registry_key_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('registry-key', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        if 'values' in observable:
            values = observable['values'][0]
            for feature, mapping in self._mapping.registry_key_values_object_mapping().items():
                if hasattr(values, feature):
                    misp_object.add_attribute(
                        **{'value': getattr(values, feature), **mapping}
                    )
        for feature, mapping in self._mapping.registry_key_object_mapping().items():
            if hasattr(observable, feature):
                misp_object.add_attribute(
                    **{'value': getattr(observable, feature), **mapping}
                )
        self._add_misp_object(misp_object, observed_data)

    def _object_from_registry_key_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_registry_key_observable(observed_data, 'v20')

    def _object_from_registry_key_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_registry_key_observable(observed_data, 'v21')

    def _object_from_standard_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, name: str, version: str):
        misp_object = self._create_misp_object(name, observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        feature = f"{name.replace('-', '_')}_object_mapping"
        for feature, mapping in getattr(self._mapping, feature)().items():
            if hasattr(observable, feature):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(observable, feature)
                )
        self._add_misp_object(misp_object, observed_data)

    def _object_from_telegram_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_standard_observable(
            observed_data, 'telegram-account', 'v20'
        )

    def _object_from_telegram_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_standard_observable(
            observed_data, 'telegram-account', 'v21'
        )

    def _object_from_twitter_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_account_with_attachment_observable(
            observed_data, 'twitter-account', 'v20'
        )

    def _object_from_twitter_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_account_with_attachment_observable(
            observed_data, 'twitter-account', 'v21'
        )

    def _object_from_url_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_standard_observable(observed_data, 'url', 'v20')

    def _object_from_url_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_standard_observable(observed_data, 'url', 'v21')

    def _object_from_user_account_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('user-account', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        for feature, mapping in self._mapping.user_account_object_mapping().items():
            if hasattr(observable, feature):
                if feature.startswith('x_misp_'):
                    self._populate_object_attributes_with_data(
                        misp_object,
                        mapping,
                        getattr(observable, feature)
                    )
                else:
                    self._populate_object_attributes(
                        misp_object,
                        mapping,
                        getattr(observable, feature)
                    )
        if getattr(observable, 'extensions', {}).get('unix-account-ext'):
            unix_extension = observable.extensions['unix-account-ext']
            for feature, mapping in self._mapping.user_account_unix_extension_object_mapping().items():
                if hasattr(unix_extension, feature):
                    self._populate_object_attributes(
                        misp_object,
                        mapping,
                        getattr(unix_extension, feature)
                    )
        self._add_misp_object(misp_object, observed_data)

    def _object_from_user_account_observable_v20(
            self, observed_data: ObservedData_v20):
        self._object_from_user_account_observable(observed_data, 'v20')

    def _object_from_user_account_observable_v21(
            self, observed_data: ObservedData_v21):
        self._object_from_user_account_observable(observed_data, 'v21')

    def _object_from_x509_observable(
            self, observed_data: _OBSERVED_DATA_TYPING, version: str):
        misp_object = self._create_misp_object('x509', observed_data)
        observable = getattr(self, f'_fetch_observables_{version}')(
            observed_data
        )
        if hasattr(observable, 'hashes'):
            for key, value in observable.hashes.items():
                hash_type = key.replace('-', '').lower()
                misp_object.add_attribute(
                    **{
                        'type': f'x509-fingerprint-{hash_type}',
                        'object_relation': f'x509-fingerprint-{hash_type}',
                        'value': value
                    }
                )
        for feature, mapping in self._mapping.x509_object_mapping().items():
            if hasattr(observable, feature):
                misp_object.add_attribute(
                    **{'value': getattr(observable, feature), **mapping}
                )
        if hasattr(observable, 'x509_v3_extensions'):
            for values in observable.x509_v3_extensions.subject_alternative_name.split(','):
                key, value = values.split('=')
                misp_object.add_attribute(
                    **{
                        'value': value,
                        **self._mapping.x509_subject_alternative_name_mapping(key)
                    }
                )
        self._add_misp_object(misp_object, observed_data)

    def _object_from_x509_observable_v20(self, observed_data: ObservedData_v20):
        self._object_from_x509_observable(observed_data, 'v20')

    def _object_from_x509_observable_v21(self, observed_data: ObservedData_v21):
        self._object_from_x509_observable(observed_data, 'v21')

    ################################################################################
    #                          PATTERNS PARSING FUNCTIONS                          #
    ################################################################################

    def _attribute_from_AS_indicator(self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = self._parse_AS_value(
            self._extract_attribute_value_from_pattern(indicator.pattern[1:-1])
        )
        self._add_misp_attribute(attribute, indicator)

    def _attribute_from_attachment_indicator(self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        pattern = indicator.pattern[1:-1]
        if ' AND ' in pattern:
            pattern, data_pattern = pattern.split(' AND ')
            attribute['data'] = self._extract_attribute_value_from_pattern(
                data_pattern
            )
        attribute['value'] = self._extract_attribute_value_from_pattern(pattern)
        self._add_misp_attribute(attribute, indicator)

    def _attribute_from_double_pattern_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        domain_pattern, pattern = indicator.pattern[1:-1].split(' AND ')
        domain_value = self._extract_attribute_value_from_pattern(
            domain_pattern
        )
        value = self._extract_attribute_value_from_pattern(pattern)
        attribute['value'] = f'{domain_value}|{value}'
        self._add_misp_attribute(attribute, indicator)

    def _attribute_from_dual_pattern_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        pattern = indicator.pattern[1:-1].split(' AND ')[1]
        attribute['value'] = self._extract_attribute_value_from_pattern(pattern)
        self._add_misp_attribute(attribute, indicator)

    def _attribute_from_filename_hash_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            if 'file:name = ' in pattern:
                filename = self._extract_attribute_value_from_pattern(pattern)
            elif 'file:hashes.' in pattern:
                hash_value = self._extract_attribute_value_from_pattern(pattern)
        try:
            attribute['value'] = f"{filename}|{hash_value}"
        except NameError:
            raise AttributeFromPatternParsingError(indicator.id)
        self._add_misp_attribute(attribute, indicator)

    def _attribute_from_ip_port_indicator(self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        values = [
            self._extract_attribute_value_from_pattern(pattern) for pattern
            in indicator.pattern[1:-1].split(' AND ')[1:]
        ]
        attribute['value'] = '|'.join(values)
        self._add_misp_attribute(attribute, indicator)

    def _attribute_from_malware_sample_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        pattern = indicator.pattern[1:-1]
        filename_pattern, md5_pattern, *pattern = pattern.split(' AND ')
        filename_value = self._extract_attribute_value_from_pattern(
            filename_pattern
        )
        md5_value = self._extract_attribute_value_from_pattern(md5_pattern)
        attribute['value'] = f'{filename_value}|{md5_value}'
        if pattern:
            attribute['data'] = self._extract_attribute_value_from_pattern(
                pattern[0]
            )
        self._add_misp_attribute(attribute, indicator)

    def _attribute_from_patterning_language_indicator(
            self, indicator: Indicator_v21):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = indicator.pattern
        self._add_misp_attribute(attribute, indicator)

    def _attribute_from_simple_pattern_indicator(
            self, indicator: _INDICATOR_TYPING):
        attribute = self._create_attribute_dict(indicator)
        attribute['value'] = self._extract_attribute_value_from_pattern(
            indicator.pattern[1:-1]
        )
        self._add_misp_attribute(attribute, indicator)

    def _object_from_account_indicator(
            self, indicator: _INDICATOR_TYPING, name: str):
        misp_object = self._create_misp_object(name, indicator)
        mapping = getattr(
            self._mapping, f"{name.replace('-', '_')}_pattern_mapping"
        )
        for pattern in indicator.pattern[1:-1].split(' AND '):
            key, value = self._extract_features_from_pattern(pattern)
            attribute = mapping(key)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
        self._add_misp_object(misp_object, indicator)

    def _object_from_account_with_attachment_indicator(
            self, indicator: _INDICATOR_TYPING, name: str):
        misp_object = self._create_misp_object(name, indicator)
        mapping = getattr(
            self._mapping, f"{name.replace('-', '_')}_pattern_mapping"
        )
        attachments: defaultdict = defaultdict(dict)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            key, value = self._extract_features_from_pattern(pattern)
            if key.startswith('x_misp_') and '.' in key:
                feature, key = key.split('.')
                attachments[feature][key] = value
            else:
                attribute = mapping(key)
                if attribute is not None:
                    misp_object.add_attribute(**{'value': value, **attribute})
        if attachments:
            for feature, attribute in attachments.items():
                attribute.update(mapping(feature))
                misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, indicator)

    def _object_from_android_app_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_standard_pattern(indicator, 'android-app')

    def _object_from_asn_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('asn', indicator)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            misp_object.add_attribute(
                **{
                    'value': self._parse_AS_value(value) if feature == 'number' else value,
                    **self._mapping.asn_pattern_mapping(feature)
                }
            )
        self._add_misp_object(misp_object, indicator)

    def _object_from_cpe_asset_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_standard_pattern(indicator, 'cpe-asset')

    def _object_from_credential_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_standard_pattern(indicator, 'credential')

    def _object_from_domain_ip_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('domain-ip', indicator)
        mapping = self._mapping.domain_ip_pattern_mapping
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'resolves_to_refs' in feature:
                misp_object.add_attribute(
                    **{'value': value, **self._mapping.ip_attribute()}
                )
            else:
                attribute = mapping(feature)
                if attribute is not None:
                    misp_object.add_attribute(
                        **{'value': value, **attribute}
                    )
        self._add_misp_object(misp_object, indicator)

    def _object_from_email_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('email', indicator)
        mapping = self._mapping.email_pattern_mapping
        attachments: defaultdict = defaultdict(dict)
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'body_multipart[' in feature:
                index = feature[15]
                identifier = feature.split('.')[1]
                if identifier == 'content_disposition':
                    attachments[index]['object_relation'] = value
                else:
                    key = 'value' if feature.split('.')[-1] == 'name' else 'data'
                    attachments[index][key] = value
                continue
            if '_refs[' in feature:
                ref_type = feature.split('[')[0]
                misp_object.add_attribute(
                    **{
                        'value': value,
                        **mapping(ref_type)[feature.split('.')[-1]]
                    }
                )
                continue
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
        if attachments:
            for attribute in attachments.values():
                attribute['type'] = 'attachment'
                misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, indicator)

    def _object_from_file_extension_pattern(
            self, extension: dict, indicator: _INDICATOR_TYPING) -> str:
        pe_object = self._create_misp_object('pe')
        pe_object.from_dict(**self._parse_timeline(indicator))
        if 'address_of_entry_point' in extension['pe']:
            pe_object.add_attribute(
                **{
                    'value': extension['pe']['address_of_entry_point'],
                    **self._mapping.entrypoint_address_attribute()
                }
            )
        for feature, value in extension['pe'].items():
            attribute = self._mapping.pe_pattern_mapping(feature)
            if attribute is not None:
                pe_object.add_attribute(**{'value': value,**attribute})
        misp_object = self._add_misp_object(pe_object, indicator)
        for section in extension.get('sections').values():
            section_object = self._create_misp_object('pe-section')
            section_object.from_dict(**self._parse_timeline(indicator))
            for feature, value in section.items():
                attribute = self._mapping.pe_section_pattern_mapping(feature)
                if attribute is not None:
                    section_object.add_attribute(
                        **{'value': value, **attribute}
                    )
                    continue
                section_object.add_attribute(
                    **{
                        'value': value,
                        **self._mapping.file_hashes_mapping(feature)
                    }
                )
            self._add_misp_object(section_object, indicator)
            misp_object.add_reference(section_object.uuid, 'includes')
        return misp_object.uuid

    def _object_from_file_indicator(self, indicator: _INDICATOR_TYPING):
        file_object = self._create_misp_object('file', indicator)
        mapping = self._mapping.file_pattern_mapping
        attachment: dict
        attachments: list = []
        extension: defaultdict = defaultdict(lambda: defaultdict(dict))
        in_attachment: bool = False
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if "extensions.'windows-pebinary-ext'." in feature:
                if '.sections[' in feature:
                    parsed = feature.split('.')[2:]
                    extension['sections'][parsed[0][-2]][parsed[-1]] = value
                else:
                    extension['pe'][feature.split('.')[-1]] = value
                continue
            if pattern.startswith('('):
                attachment = {feature: value}
                in_attachment = True
                continue
            if value.endswith("')"):
                attachment[feature] = value[:-2]
                attachments.append(attachment)
                in_attachment = False
                continue
            if in_attachment:
                attachment[feature] = value
            else:
                attribute = mapping(feature)
                if attribute is not None:
                    file_object.add_attribute(**{'value': value, **attribute})
        if attachments:
            for attachment in attachments:
                attribute = {'value': attachment['content_ref.x_misp_filename']}
                if 'content_ref.payload_bin' in attachment:
                    attribute['data'] = attachment['content_ref.payload_bin']
                if 'content_ref.hashes.MD5' in attachment:
                    attribute.update(
                        {
                            'type': 'malware-sample',
                            'object_relation': 'malware-sample',
                            'value': f"{attribute['value']}|{attachment['content_ref.hashes.MD5']}"
                        }
                    )
                else:
                    attribute.update(
                        {
                            'type': 'attachment',
                            'object_relation': 'attachment'
                        }
                    )
                file_object.add_attribute(**attribute)
        misp_object = self._add_misp_object(file_object, indicator)
        if extension:
            pe_uuid = self._object_from_file_extension_pattern(
                extension, indicator
            )
            misp_object.add_reference(pe_uuid, 'includes')

    def _object_from_facebook_account_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_account_with_attachment_indicator(
            indicator, 'facebook-account'
        )

    def _object_from_github_user_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_account_with_attachment_indicator(
            indicator, 'github-user'
        )

    def _object_from_gitlab_user_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_account_indicator(indicator, 'gitlab-user')

    def _object_from_http_request_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('http-request', indicator)
        mapping = self._mapping.http_request_pattern_mapping
        reference: dict
        request_values = []
        request_value = "extensions.'http-request-ext'.request_value"
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if pattern.startswith('('):
                reference = dict(
                    self._parse_http_request_reference(feature, value)
                )
                continue
            if pattern.endswith(')'):
                reference.update(
                    self._parse_http_request_reference(feature, value)
                )
                misp_object.add_attribute(**reference)
                continue
            if feature == request_value:
                request_values.append(value)
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
        if request_values:
            if len(request_values) == 1:
                misp_object.add_attribute(
                    **{
                        'value': request_values[0],
                        **self._mapping.uri_attribute()
                    }
                )
            else:
                value1, value2 = request_values
                args = (value1, value2) if value1 in value2 else (value2, value1)
                self._parse_http_request_values(misp_object, *args)
        self._add_misp_object(misp_object, indicator)

    def _object_from_image_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('image', indicator)
        mapping = self._mapping.image_pattern_mapping
        attachment = {'type': 'attachment', 'object_relation': 'attachment'}
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'payload_bin' in feature:
                attachment['data'] = value
                continue
            if 'x_misp_filename' in feature:
                attachment['value'] = value
                continue
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
        if 'data' in attachment or 'value' in attachment:
            misp_object.add_attribute(**attachment)
        self._add_misp_object(misp_object, indicator)

    def _object_from_ip_port_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('ip-port', indicator)
        mapping = self._mapping.ip_port_pattern_mapping
        reference: dict
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if pattern.startswith('('):
                reference = self._parse_ip_port_reference(feature, value)
                continue
            if pattern.endswith(')'):
                reference.update(
                    self._parse_ip_port_reference(feature, value[:-2])
                )
                misp_object.add_attribute(**reference)
                continue
            if 'protocol' in feature:
                misp_object.add_attribute(
                    **{'value': value, **self._mapping.protocol_attribute()}
                )
                continue
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
        self._add_misp_object(misp_object, indicator)

    def _object_from_lnk_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('lnk', indicator)
        mapping = self._mapping.lnk_pattern_mapping
        attachment: dict = {}
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'content_ref.' in feature:
                attachment[feature.split('.')[-1]] = value
                continue
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
        if attachment:
            attribute = {
                'type': 'malware-sample',
                'object_relation': 'malware-sample',
                'value': f"{attachment['x_misp_filename']}|{attachment['MD5']}"
            }
            if 'payload_bin' in attachment:
                attribute['data'] = attachment['payload_bin']
            misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, indicator)

    def _object_from_mutex_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_standard_pattern(indicator, 'mutex')

    def _object_from_netflow_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('netflow', indicator)
        mapping = self._mapping.netflow_pattern_mapping
        reference: dict
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'src_ref.' in feature or 'dst_ref.' in feature:
                if pattern.startswith('('):
                    reference = defaultdict(dict)
                elif pattern.endswith(')'):
                    self._parse_netflow_reference(
                        reference, feature, value[:-2]
                    )
                    for attribute in reference.values():
                        misp_object.add_attribute(**attribute)
                    continue
                self._parse_netflow_reference(reference, feature, value)
                continue
            misp_object.add_attribute(
                **{
                    'value': value.upper() if 'protocols' in feature else value,
                    **mapping(feature)
                }
            )
        self._add_misp_object(misp_object, indicator)

    def _object_from_network_connection_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_network_traffic_indicator(
            'network-connection', indicator
        )

    def _object_from_network_socket_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_network_traffic_indicator(
            'network-socket', indicator
        )

    def _object_from_network_traffic_indicator(
            self, name: str, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object(name, indicator)
        name = name.replace('-', '_')
        mapping = getattr(self._mapping, f'{name}_pattern_mapping')
        reference: dict
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if pattern.startswith('('):
                reference = dict(self._parse_network_reference(feature, value))
                continue
            if pattern.endswith(')'):
                reference.update(
                    self._parse_network_reference(feature, value[:-2])
                )
                misp_object.add_attribute(**reference)
                continue
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
            else:
                getattr(self, f'_parse_{name}_pattern')(
                    misp_object, feature, value
                )
        self._add_misp_object(misp_object, indicator)

    def _object_from_parler_account_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_account_with_attachment_indicator(
            indicator, 'parler-account'
        )

    def _object_from_patterning_language_indicator(
            self, indicator: Indicator_v21):
        name = 'suricata' if indicator.pattern_type == 'snort' else indicator.pattern_type
        misp_object = self._create_misp_object(name, indicator)
        for key, mapping in getattr(self._mapping, f'{name}_object_mapping')().items():
            if hasattr(indicator, key):
                self._populate_object_attributes(
                    misp_object,
                    mapping,
                    getattr(indicator, key)
                )
        if hasattr(indicator, 'external_references') and name in ('sigma', 'suricata'):
            for reference in indicator.external_references:
                attribute = {
                    'value': reference.url,
                    **getattr(self._mapping, f'{name}_reference_attribute')()
                }
                if hasattr(reference, 'description'):
                    attribute['comment'] = reference.description
                misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, indicator)

    def _object_from_process_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('process', indicator)
        mapping = self._mapping.process_pattern_mapping
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'child_refs' in feature:
                misp_object.add_attribute(
                    **{
                        'type': 'text',
                        'object_relation': 'child-pid',
                        'value': value
                    }
                )
                continue
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
        self._add_misp_object(misp_object, indicator)

    def _object_from_reddit_account_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_account_with_attachment_indicator(
            indicator, 'reddit-account'
        )

    def _object_from_registry_key_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('registry-key', indicator)
        mapping = self._mapping.registry_key_pattern_mapping
        values_mapping = self._mapping.registry_key_values_pattern_mapping
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if 'values[0].' in feature:
                key = feature.split('.')[-1]
                attribute = values_mapping(key)
                if attribute is not None:
                    misp_object.add_attribute(**{'value': value, **attribute})
                continue
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
        self._add_misp_object(misp_object, indicator)

    def _object_from_standard_pattern(
            self, indicator: _INDICATOR_TYPING, name: str):
        misp_object = self._create_misp_object(name, indicator)
        mapping = getattr(
            self._mapping, f"{name.replace('-', '_')}_pattern_mapping"
        )
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            misp_object.add_attribute(**{'value': value, **mapping(feature)})
        self._add_misp_object(misp_object, indicator)

    def _object_from_telegram_account_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_account_indicator(indicator, 'telegram-account')

    def _object_from_twitter_account_indicator(
            self, indicator: _INDICATOR_TYPING):
        self._object_from_account_with_attachment_indicator(
            indicator, 'twitter-account'
        )

    def _object_from_url_indicator(self, indicator: _INDICATOR_TYPING):
        self._object_from_standard_pattern(indicator, 'url')

    def _object_from_user_account_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('user-account', indicator)
        attachments: defaultdict = defaultdict(dict)
        mapping = self._mapping.user_account_pattern_mapping
        extension_mapping = self._mapping.user_account_unix_extension_pattern_mapping
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            if feature.startswith('x_misp_') and '.' in feature:
                key, feature = feature.split('.')
                attachments[key][feature] = value
                continue
            if 'unix-account-ext' in feature:
                feature = feature.split('.')[-1]
                attribute = extension_mapping(feature)
                if attribute is not None:
                    misp_object.add_attribute(**{'value': value, **attribute})
                continue
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
        if attachments:
            for feature, attribute in attachments.items():
                attribute.update(mapping(feature))
                misp_object.add_attribute(**attribute)
        self._add_misp_object(misp_object, indicator)

    def _object_from_x509_indicator(self, indicator: _INDICATOR_TYPING):
        misp_object = self._create_misp_object('x509', indicator)
        mapping = self._mapping.x509_pattern_mapping
        for pattern in indicator.pattern[1:-1].split(' AND '):
            feature, value = self._extract_features_from_pattern(pattern)
            attribute = mapping(feature)
            if attribute is not None:
                misp_object.add_attribute(**{'value': value, **attribute})
            elif 'subject_alternative_name' in feature:
                subject_mapping = self._mapping.x509_subject_alternative_name_mapping
                for values in value.split(','):
                    key, value = values.split('=')
                    misp_object.add_attribute(
                        **{'value': value, **subject_mapping(key)}
                    )
        self._add_misp_object(misp_object, indicator)

    def _parse_http_request_reference(self, feature: str, value: str) -> dict:
        if feature.split('.')[1] == 'value':
            return {'value': value}
        if value == 'domain-name':
            return self._mapping.host_attribute()
        return getattr(self._mapping, f"ip_{feature.split('_')[0]}_attribute")()

    def _parse_http_request_values(
            self, misp_object: MISPObject, uri: str, url: str):
        uri_attribute = {'value': uri}
        uri_attribute.update(self._mapping.uri_attribute())
        misp_object.add_attribute(**uri_attribute)
        url_attribute = {'value': url}
        url_attribute.update(self._mapping.url_attribute())
        misp_object.add_attribute(**url_attribute)

    @staticmethod
    def _parse_ip_port_reference(feature: str, value: str) -> dict:
        if feature.split('.')[1] == 'value':
            return {'value': value}
        relation = 'domain' if value == 'domain-name' else f"ip-{feature.split('_')[0]}"
        return {'type': relation, 'object_relation': relation}

    def _parse_netflow_reference(self, reference: dict, feature: str, value: str):
        ref_type = feature.split('_')[0]
        if '_ref.type' in feature:
            relation = f'ip-{ref_type}'
            reference[relation].update(
                {'type': relation, 'object_relation': relation}
            )
        elif '_ref.value' in feature:
            reference[f'ip-{ref_type}']['value'] = value
        else:
            reference[f'{ref_type}-as'] = {
                'value': value,
                **getattr(self._mapping, f'{ref_type}_as_attribute')()
            }

    def _parse_network_connection_pattern(
            self, misp_object: MISPObject, feature: str, value: str):
        if 'protocols' in feature:
            protocol = value.upper()
            layer = self._mapping.connection_protocols(protocol)
            misp_object.add_attribute(
                **{
                    'type': 'text',
                    'object_relation': f'layer{layer}-protocol',
                    'value': protocol
                }
            )

    def _parse_network_reference(self, feature: str, value: str) -> dict:
        if feature.split('.')[1] == 'value':
            return {'value': value}
        feature = feature.split('_')[0]
        if value == 'domain-name':
            return getattr(self._mapping, f'hostname_{feature}_attribute')()
        return getattr(self._mapping, f'ip_{feature}_attribute')()

    def _parse_network_socket_pattern(
            self, misp_object: MISPObject, feature: str, value: str):
        if 'protocols' in feature:
            protocol = value.upper()
            misp_object.add_attribute(
                **{
                    'type': 'text',
                    'object_relation': 'protocol',
                    'value': protocol
                }
            )
        elif "extensions.'socket-ext'" in feature:
            key = feature.split('.')[-1]
            if value in ('True', 'true', True):
                misp_object.add_attribute(
                    **{
                        'type': 'text',
                        'object_relation': 'state',
                        'value': key.split('_')[1]
                    }
                )
            else:
                attribute = self._mapping.network_socket_extension_pattern_mapping(key)
                if attribute is not None:
                    misp_object.add_attribute(**{'value': value, **attribute})

    ################################################################################
    #                   MISP DATA STRUCTURES CREATION FUNCTIONS.                   #
    ################################################################################

    def _create_attribute_dict(self, stix_object: _SDO_TYPING) -> dict:
        attribute = self._attribute_from_labels(stix_object.labels)
        attribute.update(super()._create_attribute_dict(stix_object))
        return attribute

    @staticmethod
    def _create_attribute_from_reference_v20(
            attribute_type: str, object_relation: str,
            feature: str, reference) -> dict:
        return {
            'type': attribute_type,
            'object_relation': object_relation,
            'value': getattr(reference, feature)
        }

    def _create_attribute_from_reference_v21(
            self, attribute_type: str, object_relation: str,
            feature: str, reference) -> dict:
        return {
            'type': attribute_type,
            'object_relation': object_relation,
            'value': getattr(reference, feature),
            **self._sanitise_attribute_uuid(reference.id)
        }

    ################################################################################
    #                              UTILITY FUNCTIONS.                              #
    ################################################################################

    @staticmethod
    def _attribute_from_labels(labels: list) -> dict:
        attribute = {}
        tags = []
        for label in labels:
            if label.startswith('misp:'):
                feature, value = label.split('=')
                attribute[feature.split(':')[-1]] = value.strip('"')
            else:
                tags.append({'name': label})
        if tags:
            attribute['Tag'] = tags
        return attribute

    @staticmethod
    def _extract_attribute_value_from_pattern(pattern: str) -> str:
        return pattern.split(' = ')[1][1:-1]

    @staticmethod
    def _extract_features_from_pattern(pattern: str) -> tuple:
        identifier, value = pattern.split(' = ')
        return identifier.split(':')[1], value.strip("'")

    @staticmethod
    def _extract_galaxy_labels(labels: list) -> dict:
        for label in labels[:2]:
            if 'galaxy-type' in label:
                galaxy_type = label.split('=')[1].strip('"')
            elif 'galaxy-name' in label:
                galaxy_name = label.split('=')[1].strip('"')
        return galaxy_type, galaxy_name

    @staticmethod
    def _fetch_main_process(observables: dict) -> _PROCESS_TYPING:
        if tuple(observable.type for observable in observables.values()).count('process') == 1:
            for observable in observables.values():
                if observable.type == 'process':
                    return observable
        ref_features = ('child_refs', 'parent_ref')
        for observable in observables.values():
            if observable.type != 'process':
                continue
            if any(hasattr(observable, feature) for feature in ref_features):
                return observable

    def _fetch_observables(self, object_refs: Union[list, str]):
        if isinstance(object_refs, str):
            return self._observable[object_refs]
        if len(object_refs) == 1:
            return self._observable[object_refs[0]]
        return tuple(
            self._observable[object_ref]
            for object_ref in object_refs
        )

    @staticmethod
    def _fetch_observables_v20(observed_data: ObservedData_v20):
        observables = tuple(observed_data.objects.values())
        return observables[0] if len(observables) == 1 else observables

    def _fetch_observables_v21(self, observed_data: ObservedData_v21):
        return self._fetch_observables(observed_data.object_refs)

    @staticmethod
    def _fetch_observables_with_id_v20(observed_data: ObservedData_v20) -> dict:
        return observed_data.objects

    def _fetch_observables_with_id_v21(
            self, observed_data: ObservedData_v21) -> dict:
        return {
            ref: self._observable[ref]
            for ref in observed_data.object_refs
        }

    @staticmethod
    def _handle_external_references(external_references: list) -> dict:
        meta = defaultdict(list)
        for reference in external_references:
            if reference.get('url'):
                meta['refs'].append(reference['url'])
            feature = 'aliases' if reference.get('source_name') == 'cve' else 'external_id'
            if reference.get('external_id'):
                meta[feature].append(reference['external_id'])
        if 'external_id' in meta and len(meta['external_id']) == 1:
            meta['external_id'] = meta.pop('external_id')[0]
        return meta

    def _has_domain_custom_fields(self, observable: DomainName) -> bool:
        for feature in self._mapping.domain_ip_object_mapping():
            if feature == 'value':
                continue
            if hasattr(observable, feature):
                return True
        return False

    @staticmethod
    def _populate_object_attributes(
            misp_object: MISPObject, mapping: dict, values: Union[list, str]):
        if isinstance(values, list):
            for value in values:
                misp_object.add_attribute(**{'value': value, **mapping})
        else:
            misp_object.add_attribute(**{'value': values, **mapping})

    @staticmethod
    def _populate_object_attributes_with_data(
            misp_object: MISPObject, mapping: dict,
            values: Union[dict, list, str]):
        if isinstance(values, list):
            for value in values:
                if isinstance(value, dict):
                    attribute = deepcopy(value) if isinstance(value, dict) else {'value': value}
                    attribute.update(mapping)
                    misp_object.add_attribute(**attribute)
        else:
            attribute = deepcopy(values) if isinstance(values, dict) else {'value': values}
            attribute.update(mapping)
            misp_object.add_attribute(**attribute)
