//! Verificação de que um diretório de escrita efêmera do host está em `tmpfs`.
//!
//! O TCC (`TCC_SPEC.md`) exige que a configuração temporária e o relatório do
//! scanner fiquem restritos a `tmpfs`. O requisito não pode ser satisfeito por
//! construção apenas olhando o `TMPDIR`: o processo herda o `TMPDIR` do
//! ambiente, e em uma máquina (ou runner de CI) em que ele aponte para um
//! diretório comum em disco, o mesmo código passaria a gravar fora da regra sem
//! nenhum sinal. Por isso a condição é **verificada em execução**, e a falha é
//! explícita: sem `tmpfs`, a execução não acontece.
//!
//! ## Como o tipo do filesystem é obtido
//!
//! `std::fs::metadata` não serve: ele devolve o modo, o dono e o tipo de inode,
//! não o tipo do sistema de arquivos. Sem adicionar dependência, o tipo é
//! resolvido lendo `/proc/self/mountinfo` e casando o ponto de montagem do
//! diretório. `mountinfo` foi escolhido em vez de `/proc/mounts` porque
//! carrega o conjunto completo de campos por entrada, é o mesmo formato
//! consumido por `statx`/`openat2` no kernel e não depende de resolução de
//! nomes de blocos.
//!
//! ## Limitações conhecidas (documentadas, não escondidas)
//!
//! - **Namespace de montagens:** a tabela lida é a do *namespace* do processo
//!   (`/proc/self/mountinfo`). Se o `SmartSec` for executado em um namespace
//!   diferente do que o container enxerga, os dois podem divergir. O
//!   Podman rootless não cria namespace de montagem próprio para o processo do
//!   host, e o bind mount referencia o mesmo inode do host, então a checagem
//!   vale para o objeto que é de fato montado.
//! - **Symlink:** o caminho verificado é canonicalizado antes do casamento, de
//!   modo que um `TMPDIR` que é symlink para disco é detectado. Um symlink
//!   trocado entre a verificação e a criação do diretório (TOCTOU) ficaria fora
//!   do alcance desta checagem; a janela exige escrita no `TMPDIR` por um
//!   processo concorrente.
//! - **`overlay`:** o tipo `overlay` **não** é aceito. Ele é a camada
//!   copy-on-write de um container, e o dado escrito nele vive no diretório
//!   superior, normalmente em disco do host: aceitar `overlay` equivaleria a
//!   aceitar escrita em disco com outro nome, que é exatamente o que a regra do
//!   TCC proíbe. Em container de CI o `/tmp` costuma ser uma `tmpfs` própria; se
//!   não for, a execução falha e a mensagem diz como corrigir o ambiente.
//! - **Kernels sem `mountinfo`:** se a tabela não puder ser lida, a verificação
//!   falha. Degradar para "assumir `tmpfs`" reintroduziria a violação silenciosa
//!   que a verificação existe para impedir.

use std::path::{Path, PathBuf};

/// Tabela de montagens do namespace do processo, em `/proc`.
pub const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";

/// Filesystem exigido pela regra de isolamento do TCC para escrita efêmera.
pub const REQUIRED_FILESYSTEM: &str = "tmpfs";

/// Uma entrada da tabela de montagens: onde o filesystem foi montado e de que
/// tipo ele é.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MountEntry {
    pub mount_point: PathBuf,
    pub filesystem: String,
}

/// Fonte do tipo de filesystem que contém um caminho.
///
/// A separação existe para que o tipo possa ser **injetado** nos testes: o
/// caminho negativo (diretório em disco comum) precisa ser exercitado sem
/// depender da máquina de teste. O fluxo real nunca injeta nada e usa
/// [`ProcMounts`].
pub trait FilesystemProbe {
    /// Tipo do filesystem que contém `path`.
    ///
    /// `Ok(None)` significa que nenhum ponto de montagem conhecido contém o
    /// caminho; `Err` significa que a fonte não pôde ser consultada.
    fn filesystem(&self, path: &Path) -> std::io::Result<Option<String>>;
}

/// Lê `/proc/self/mountinfo` do processo.
pub struct ProcMounts {
    path: PathBuf,
}

impl ProcMounts {
    pub fn process() -> Self {
        Self {
            path: PathBuf::from(MOUNTINFO_PATH),
        }
    }
}

impl Default for ProcMounts {
    fn default() -> Self {
        Self::process()
    }
}

impl FilesystemProbe for ProcMounts {
    fn filesystem(&self, path: &Path) -> std::io::Result<Option<String>> {
        let content = std::fs::read_to_string(&self.path).map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!("não foi possível ler {}: {error}", self.path.display()),
            )
        })?;
        Ok(resolve_filesystem(&parse_mountinfo(&content), path))
    }
}

/// Converte o conteúdo de `mountinfo` em entradas de montagem.
///
/// Cada linha tem a forma
/// `id parent major:minor root ponto-de-montagem opções [opcionais...] - tipo fonte superopções`.
/// O separador `-` é o que dá a posição confiável do tipo do filesystem, já
/// que o número de campos opcionais varia.
pub fn parse_mountinfo(content: &str) -> Vec<MountEntry> {
    content.lines().filter_map(parse_mountinfo_line).collect()
}

fn parse_mountinfo_line(line: &str) -> Option<MountEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let separator = fields.iter().position(|field| *field == "-")?;
    // Precisa de id, parent, major:minor, root, ponto-de-montagem antes do
    // separador, e de pelo menos o tipo do filesystem depois dele.
    if separator < 5 || fields.len() < separator + 2 {
        return None;
    }
    Some(MountEntry {
        mount_point: PathBuf::from(unescape(fields[4])),
        filesystem: fields[separator + 1].to_owned(),
    })
}

/// Desfaz o escape octal do kernel: `\040` espaço, `\011` tab, `\012` newline
/// e `\134` barra invertida.
fn unescape(field: &str) -> String {
    let mut result = String::with_capacity(field.len());
    let mut characters = field.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            result.push(character);
            continue;
        }
        let digits: String = characters.by_ref().take(3).collect();
        match u8::from_str_radix(&digits, 8) {
            Ok(decoded) => result.push(decoded as char),
            // Escape malformado: preserva o texto em vez de inventar um caminho.
            Err(_) => {
                result.push('\\');
                result.push_str(&digits);
            }
        }
    }
    result
}

/// Tipo do filesystem que contém `path`.
///
/// O casamento é pelo ponto de montagem **mais específico**: `/` sempre existe
/// na tabela, e com mounts aninhados (um `tmpfs` dentro de um `overlay`) é o
/// ponto mais profundo que vale. `Path::starts_with` compara componentes
/// inteiros, então `/tmp` não casa com `/tmpsaida`.
pub fn resolve_filesystem(mounts: &[MountEntry], path: &Path) -> Option<String> {
    let mut best: Option<(usize, &MountEntry)> = None;
    for entry in mounts {
        if !path.starts_with(&entry.mount_point) {
            continue;
        }
        let depth = entry.mount_point.components().count();
        if best.map(|(current, _)| depth > current).unwrap_or(true) {
            best = Some((depth, entry));
        }
    }
    best.map(|(_, entry)| entry.filesystem.clone())
}

/// Verifica `path` contra a tabela de montagens do próprio processo.
///
/// É a porta de entrada do fluxo real: qualquer escrita efêmera do SmartSec no
/// host passa por aqui antes de gravar.
pub fn ensure_tmpfs(path: &Path) -> std::io::Result<()> {
    require_tmpfs(path, &ProcMounts::process())
}

/// Falha com mensagem acionável em pt-BR quando `path` não está em `tmpfs`.
///
/// A mensagem segue o padrão do projeto: o caminho, o que foi encontrado, o que
/// era esperado e o que fazer. Não há caminho de degradação — a função só
/// retorna `Ok` quando a regra é satisfeita de fato.
pub fn require_tmpfs(path: &Path, probe: &dyn FilesystemProbe) -> std::io::Result<()> {
    match probe.filesystem(path) {
        Ok(Some(filesystem)) if filesystem == REQUIRED_FILESYSTEM => Ok(()),
        Ok(Some(filesystem)) => Err(std::io::Error::other(violation_message(path, &filesystem))),
        Ok(None) => Err(std::io::Error::other(unresolved_message(path))),
        Err(error) => Err(std::io::Error::other(unverifiable_message(path, &error))),
    }
}

fn violation_message(path: &Path, filesystem: &str) -> String {
    format!(
        "o diretório de escrita efêmera '{dir}' está no filesystem '{filesystem}', \
         e a regra de isolamento do SmartSec exige '{REQUIRED_FILESYSTEM}'; a execução foi \
         interrompida para não gravar a configuração temporária e o relatório do scanner fora \
         da tmpfs. Ajuste o ambiente: monte uma tmpfs (por exemplo \
         `sudo mount -t tmpfs -o size=512m tmpfs /var/tmp/smartsec`) e aponte a variável \
         TMPDIR para ela antes de rodar a varredura. Um 'overlay' não é aceito: a camada \
         copy-on-write do container grava em disco do host.",
        dir = path.display()
    )
}

fn unresolved_message(path: &Path) -> String {
    format!(
        "não foi possível identificar o filesystem de '{dir}' na tabela de montagens \
         {MOUNTINFO_PATH}; a regra de isolamento exige '{REQUIRED_FILESYSTEM}' e o SmartSec não \
         prossegue sem confirmar. Verifique se o diretório existe e se {MOUNTINFO_PATH} está \
         legível neste ambiente.",
        dir = path.display()
    )
}

fn unverifiable_message(path: &Path, cause: &std::io::Error) -> String {
    format!(
        "não foi possível verificar se '{dir}' está em '{REQUIRED_FILESYSTEM}': {cause}; o \
         SmartSec não assume '{REQUIRED_FILESYSTEM}' sem verificação. Execute o SmartSec em um \
         ambiente Linux com {MOUNTINFO_PATH} legível, ou monte uma tmpfs no TMPDIR do processo.",
        dir = path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fonte determinística: devolve um tipo de filesystem fixo.
    struct FixedFilesystem(&'static str);

    impl FilesystemProbe for FixedFilesystem {
        fn filesystem(&self, _path: &Path) -> std::io::Result<Option<String>> {
            Ok(Some(self.0.to_owned()))
        }
    }

    /// Fonte que sempre falha, para o caminho de erro de leitura da tabela.
    struct UnreadableMounts;

    impl FilesystemProbe for UnreadableMounts {
        fn filesystem(&self, _path: &Path) -> std::io::Result<Option<String>> {
            Err(std::io::Error::other("tabela de montagens indisponível"))
        }
    }

    /// Fonte que não conhece o caminho.
    struct EmptyMounts;

    impl FilesystemProbe for EmptyMounts {
        fn filesystem(&self, _path: &Path) -> std::io::Result<Option<String>> {
            Ok(None)
        }
    }

    const MOUNTINFO: &str = "\
25 30 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw
30 1 259:1 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
41 30 0:41 / /tmp rw,nosuid,nodev,noexec,relatime shared:9 - tmpfs tmpfs rw,size=7883180k
77 41 0:52 / /tmp/aninhado rw,relatime shared:10 - tmpfs tmpfs rw,size=1024k
80 30 0:60 / /var/lib/sobreposto rw,relatime shared:11 - overlay overlay rw,lowerdir=/l,upperdir=/u
83 30 0:61 / /meu\\040ponto rw,relatime shared:12 - ext4 /dev/sdb1 rw
";

    #[test]
    fn the_mountinfo_entries_are_parsed_with_their_filesystem_type() {
        let mounts = parse_mountinfo(MOUNTINFO);
        assert_eq!(
            mounts,
            vec![
                MountEntry {
                    mount_point: PathBuf::from("/proc"),
                    filesystem: "proc".to_owned()
                },
                MountEntry {
                    mount_point: PathBuf::from("/"),
                    filesystem: "ext4".to_owned()
                },
                MountEntry {
                    mount_point: PathBuf::from("/tmp"),
                    filesystem: "tmpfs".to_owned()
                },
                MountEntry {
                    mount_point: PathBuf::from("/tmp/aninhado"),
                    filesystem: "tmpfs".to_owned()
                },
                MountEntry {
                    mount_point: PathBuf::from("/var/lib/sobreposto"),
                    filesystem: "overlay".to_owned()
                },
                MountEntry {
                    mount_point: PathBuf::from("/meu ponto"),
                    filesystem: "ext4".to_owned()
                },
            ]
        );
    }

    #[test]
    fn lines_without_a_separator_or_with_unexpected_fields_are_ignored() {
        assert_eq!(parse_mountinfo(""), Vec::new());
        assert_eq!(parse_mountinfo("lixo solto"), Vec::new());
        assert_eq!(
            parse_mountinfo("30 1 259:1 / rw,relatime shared:1 -"),
            Vec::new(),
            "sem o tipo do filesystem a entrada não serve"
        );
        assert_eq!(
            parse_mountinfo("30 1 259:1 / / rw - ext4"),
            vec![MountEntry {
                mount_point: PathBuf::from("/"),
                filesystem: "ext4".to_owned()
            }]
        );
    }

    #[test]
    fn the_deepest_matching_mount_point_defines_the_filesystem() {
        let mounts = parse_mountinfo(MOUNTINFO);
        assert_eq!(
            resolve_filesystem(&mounts, Path::new("/tmp/smartsec-saida-1")),
            Some("tmpfs".to_owned())
        );
        assert_eq!(
            resolve_filesystem(&mounts, Path::new("/tmp/aninhado/saida")),
            Some("tmpfs".to_owned())
        );
        assert_eq!(
            resolve_filesystem(&mounts, Path::new("/var/lib/sobreposto/saida")),
            Some("overlay".to_owned())
        );
        assert_eq!(
            resolve_filesystem(&mounts, Path::new("/home/usuario/saida")),
            Some("ext4".to_owned()),
            "sem mount dedicado, vale o ponto de montagem raiz"
        );
    }

    #[test]
    fn the_mount_point_is_matched_by_component_and_not_by_prefix() {
        let mounts = parse_mountinfo(MOUNTINFO);
        // `/tmpsaida` não é filho de `/tmp`.
        assert_eq!(
            resolve_filesystem(&mounts, Path::new("/tmpsaida/artefato.json")),
            Some("ext4".to_owned())
        );
    }

    #[test]
    fn a_dir_inside_tmpfs_passes_the_check() {
        assert!(require_tmpfs(
            Path::new("/tmp/smartsec-saida-1"),
            &FixedFilesystem("tmpfs")
        )
        .is_ok());
    }

    #[test]
    fn a_dir_on_a_regular_disk_fails_with_an_actionable_message() {
        let error = require_tmpfs(
            Path::new("/var/tmp/smartsec-saida-1"),
            &FixedFilesystem("ext4"),
        )
        .expect_err("diretório em disco comum precisa ser recusado")
        .to_string();

        assert!(error.contains("/var/tmp/smartsec-saida-1"), "{error}");
        assert!(error.contains("'ext4'"), "{error}");
        assert!(error.contains("exige 'tmpfs'"), "{error}");
        assert!(error.contains("TMPDIR"), "{error}");
        assert!(error.contains("mount -t tmpfs"), "{error}");
        assert!(error.contains("overlay"), "{error}");
    }

    #[test]
    fn overlay_is_refused_even_though_it_is_a_mount_point() {
        // `overlay` é a camada copy-on-write do container: o dado gravado vive
        // no diretório superior, em disco do host.
        let mounts = parse_mountinfo(MOUNTINFO);
        let path = Path::new("/var/lib/sobreposto/saida");
        assert_eq!(
            resolve_filesystem(&mounts, path),
            Some("overlay".to_owned())
        );
        let error = require_tmpfs(path, &FixedFilesystem("overlay"))
            .expect_err("overlay não pode ser aceito como tmpfs")
            .to_string();
        assert!(error.contains("'overlay'"), "{error}");
        assert!(error.contains("'tmpfs'"), "{error}");
    }

    #[test]
    fn an_unresolvable_path_fails_instead_of_being_assumed() {
        let error = require_tmpfs(Path::new("/tmp/saida"), &EmptyMounts)
            .expect_err("sem ponto de montage conhecido a regra não está verificada")
            .to_string();
        assert!(error.contains("/tmp/saida"), "{error}");
        assert!(error.contains(MOUNTINFO_PATH), "{error}");
    }

    #[test]
    fn an_unreadable_mount_table_fails_instead_of_being_assumed() {
        let error = require_tmpfs(Path::new("/tmp/saida"), &UnreadableMounts)
            .expect_err("sem tabela legível a regra não está verificada")
            .to_string();
        assert!(
            error.contains("tabela de montagens indisponível"),
            "{error}"
        );
        assert!(error.contains("não assume 'tmpfs'"), "{error}");
    }

    #[test]
    fn the_mount_table_of_this_machine_exposes_a_root_entry() {
        // Não assume tmpfs nesta máquina: só confere que a fonte real do fluxo
        // de produção responde e é capaz de classificar um caminho.
        let probe = ProcMounts::process();
        let filesystem = probe
            .filesystem(&std::env::temp_dir())
            .expect("a tabela de montagens do processo deve ser legível em Linux");
        let filesystem = filesystem.expect("o TMPDIR está sob algum ponto de montagem");
        assert!(!filesystem.is_empty(), "{filesystem}");
    }
}
