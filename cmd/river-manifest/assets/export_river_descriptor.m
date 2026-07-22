function river_export_descriptor(buildDir, outputFile)
% Export the documented Code Descriptor API to portable JSON. buildDir is
% the directory containing codedescriptor.dmr; the DMR format itself is not
% parsed or reverse engineered.
descriptor = coder.getCodeDescriptor(buildDir);
result.model_name = char(descriptor.ModelName);
result.data = struct('category', {}, 'graphical_name', {}, 'sid', {}, ...
    'implementation', {}, 'unit', {});

categories = descriptor.getDataInterfaceTypes();
for categoryIndex = 1:numel(categories)
    category = categories{categoryIndex};
    interfaces = descriptor.getDataInterfaces(category);
    for interfaceIndex = 1:numel(interfaces)
        interface = interfaces(interfaceIndex);
        item.category = char(category);
        item.graphical_name = stringProperty(interface, 'GraphicalName');
        item.sid = stringProperty(interface, 'SID');
        item.unit = stringProperty(interface, 'Unit');
        item.implementation = implementationName(interface);
        result.data(end + 1) = item; %#ok<AGROW>
    end
end

file = fopen(outputFile, 'w');
if file < 0
    error('River:DescriptorExport', 'Cannot open descriptor output file');
end
cleanup = onCleanup(@() fclose(file));
fwrite(file, jsonencode(result, PrettyPrint=true), 'char');
end

function value = implementationName(interface)
value = '';
if ~isprop(interface, 'Implementation') || isempty(interface.Implementation)
    return;
end
implementation = interface.Implementation;
for candidate = {'Identifier', 'ElementIdentifier', 'Name'}
    value = stringProperty(implementation, candidate{1});
    if ~isempty(value)
        return;
    end
end
end

function value = stringProperty(object, name)
value = '';
if ~isprop(object, name)
    return;
end
raw = object.(name);
if isempty(raw)
    return;
end
try
    value = char(string(raw));
catch
    value = '';
end
end
